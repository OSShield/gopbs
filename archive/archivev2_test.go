//go:build linux

package archive_test

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/scheiblingco/gopbs/archive"
	"github.com/scheiblingco/gopbs/pxar"
	"github.com/scheiblingco/gopbs/scan"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

// generateV2 consumes both split streams concurrently (metadata emission can
// await payload dispatch progress, so sequential draining may stall).
func generateV2(t *testing.T, a *archive.Archive) (meta, payload []byte) {
	t.Helper()
	metaRC, payloadRC, err := a.GenerateV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer metaRC.Close()
	defer payloadRC.Close()

	var (
		wg         sync.WaitGroup
		payloadErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload, payloadErr = io.ReadAll(payloadRC)
	}()
	meta, err = io.ReadAll(metaRC)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if payloadErr != nil {
		t.Fatal(payloadErr)
	}
	return meta, payload
}

// Split-archive structure: format version record, refs resolving to
// contiguous in-order payload records, v2 goodbye semantics (verified inside
// the parser), hardlinks, and the estimate invariant — in both generation
// modes.
func TestGenerateV2Structure(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("split archives bind offsets from dispatched sizes")
	if err := os.WriteFile(filepath.Join(root, "b.txt"), content, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "data.bin"), bytes.Repeat([]byte{7}, 3000), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "hollow.bin"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../b.txt", filepath.Join(root, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "b.txt"), filepath.Join(root, "sub", "z.hard")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "a.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, workers := range []int{1, 4} {
		a, err := archive.New(archive.Options{Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}

		metaEst, payloadEst, err := a.EstimatedSizeV2()
		if err != nil {
			t.Fatal(err)
		}
		meta, payload := generateV2(t, a)
		if int64(len(meta)) != metaEst || int64(len(payload)) != payloadEst {
			t.Errorf("workers=%d: emitted %d+%d bytes, estimate was %d+%d",
				workers, len(meta), len(payload), metaEst, payloadEst)
		}

		dec, err := parseArchiveV2(meta, payload)
		if err != nil {
			t.Fatalf("workers=%d: %v", workers, err)
		}

		file := dec.find("b.txt")
		if file == nil || !bytes.Equal(file.content, content) {
			t.Fatalf("workers=%d: b.txt content mismatch: %+v", workers, file)
		}
		if data := dec.find("sub/data.bin"); data == nil || len(data.content) != 3000 {
			t.Errorf("workers=%d: data.bin: %+v", workers, data)
		}
		if e := dec.find("sub/hollow.bin"); e == nil || len(e.content) != 0 {
			t.Errorf("workers=%d: empty file: %+v", workers, e)
		}
		if l := dec.find("sub/link"); l == nil || l.symlink != "../b.txt" {
			t.Errorf("workers=%d: symlink: %+v", workers, l)
		}

		hl := dec.find("sub/z.hard")
		if hl == nil || hl.hardlink.target != "b.txt" {
			t.Fatalf("workers=%d: hardlink: %+v", workers, hl)
		}
		if got := hl.start - hl.hardlink.offset; got != file.start {
			t.Errorf("workers=%d: hardlink offset resolves to %d, target at %d", workers, got, file.start)
		}
	}
}

// A virtual root combining directory content and streams.
func TestGenerateV2Streams(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	streamData := bytes.Repeat([]byte("v2"), 5000)

	a, err := archive.New(archive.Options{Name: "combo"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("s.bin", int64(len(streamData)), bytes.NewReader(streamData)); err != nil {
		t.Fatal(err)
	}

	meta, payload := generateV2(t, a)
	dec, err := parseArchiveV2(meta, payload)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(root)
	if f := dec.find(base + "/f.txt"); f == nil || string(f.content) != "payload" {
		t.Errorf("file under virtual root: %+v", f)
	}
	if s := dec.find("s.bin"); s == nil || !bytes.Equal(s.content, streamData) {
		t.Errorf("stream: %+v", s)
	}
}

// maskRootMtimeV2 is maskRootMtime for the metadata stream, where the format
// version record shifts the root entry by 24 bytes.
func maskRootMtimeV2(data []byte) []byte {
	if len(data) >= 76 {
		clear(data[64:76])
	}
	return data
}

// Async generation must produce byte-identical streams to sync generation.
func TestAsyncEqualsSyncV2(t *testing.T) {
	if testing.Short() {
		t.Skip("randomized equality sweep")
	}
	generateV2With := func(root string, workers int, buffer int64, stream []byte) (m, p []byte) {
		a, err := archive.New(archive.Options{Name: "eq", Workers: workers, Buffer: buffer})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		if stream != nil {
			if err := a.AddStream("stream.bin", int64(len(stream)), bytes.NewReader(stream)); err != nil {
				t.Fatal(err)
			}
		}
		return generateV2(t, a)
	}

	for seed := int64(0); seed < 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		root := genTree(t, rng)
		stream := make([]byte, rng.Intn(100_000))
		rng.Read(stream)

		workers := 2 + int(seed%7)
		var buffer int64
		switch seed % 3 {
		case 1:
			buffer = 1 // clamped to the 2-chunk minimum: maximal contention
		case 2:
			buffer = 4 << 20
		}

		// Single-directory archives: no virtual root, so equality is exact.
		syncMeta, syncPayload := generateV2With(root, 1, 0, nil)
		asyncMeta, asyncPayload := generateV2With(root, workers, buffer, nil)
		if !bytes.Equal(syncMeta, asyncMeta) {
			t.Fatalf("seed %d (workers=%d buffer=%d): metadata stream differs (%d vs %d bytes)",
				seed, workers, buffer, len(syncMeta), len(asyncMeta))
		}
		if !bytes.Equal(syncPayload, asyncPayload) {
			t.Fatalf("seed %d (workers=%d buffer=%d): payload stream differs (%d vs %d bytes)",
				seed, workers, buffer, len(syncPayload), len(asyncPayload))
		}
		if seed%10 == 0 {
			if _, err := parseArchiveV2(asyncMeta, asyncPayload); err != nil {
				t.Fatalf("seed %d: async split archive does not parse: %v", seed, err)
			}
		}

		// Virtual-root archives with a stream: equal modulo the root's
		// plan-time mtime.
		if seed%5 == 0 {
			syncMeta, syncPayload = generateV2With(root, 1, 0, stream)
			asyncMeta, asyncPayload = generateV2With(root, workers, buffer, append([]byte(nil), stream...))
			if !bytes.Equal(maskRootMtimeV2(syncMeta), maskRootMtimeV2(asyncMeta)) {
				t.Fatalf("seed %d: metadata stream differs beyond the root mtime", seed)
			}
			if !bytes.Equal(syncPayload, asyncPayload) {
				t.Fatalf("seed %d: payload stream differs", seed)
			}
		}
	}
}

// Files changed between scan and generation: refs must carry the re-bound
// sizes, keeping both streams consistent.
func TestGenerateV2LateBindingRebindsSize(t *testing.T) {
	root := t.TempDir()
	grow := filepath.Join(root, "a.grow")
	shrink := filepath.Join(root, "b.shrink")
	if err := os.WriteFile(grow, bytes.Repeat([]byte("g"), 100), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shrink, bytes.Repeat([]byte("s"), 5000), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, workers := range []int{1, 4} {
		a, err := archive.New(archive.Options{Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		// The estimate scans now; the files change before generation scans
		// again, so this stays a pure size-mismatch exercise for the parser.
		if _, _, err := a.EstimatedSizeV2(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(grow, bytes.Repeat([]byte("G"), 9000), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(shrink, []byte("S"), 0o644); err != nil {
			t.Fatal(err)
		}

		meta, payload := generateV2(t, a)
		dec, err := parseArchiveV2(meta, payload)
		if err != nil {
			t.Fatalf("workers=%d: %v", workers, err)
		}
		if f := dec.find("a.grow"); f == nil || len(f.content) != 9000 {
			t.Errorf("workers=%d: grown file: %d bytes", workers, len(f.content))
		}
		if f := dec.find("b.shrink"); f == nil || string(f.content) != "S" {
			t.Errorf("workers=%d: shrunk file: %q", workers, f.content)
		}

		// Restore the tree for the next worker mode.
		if err := os.WriteFile(grow, bytes.Repeat([]byte("g"), 100), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(shrink, bytes.Repeat([]byte("s"), 5000), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// An unreadable payload must fail both streams, in both generation modes.
func TestGenerateV2Errors(t *testing.T) {
	defer goleak.VerifyNone(t)
	root := t.TempDir()
	locked := filepath.Join(root, "locked.bin")
	if err := os.WriteFile(locked, []byte("no"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		t.Skip("root reads anything")
	}

	for _, workers := range []int{1, 4} {
		// Quota lookups also open files, so skip them: the scan must succeed
		// and the failure must come from the payload open at generation time.
		a, err := archive.New(archive.Options{Workers: workers, Scan: scan.Options{SkipQuotaProjIDs: true}})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		metaRC, payloadRC, err := a.GenerateV2(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var (
			wg      sync.WaitGroup
			metaErr error
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, metaErr = io.ReadAll(metaRC)
		}()
		_, payloadErr := io.ReadAll(payloadRC)
		wg.Wait()
		metaRC.Close()
		payloadRC.Close()

		if payloadErr == nil || !strings.Contains(payloadErr.Error(), "permission denied") {
			t.Errorf("workers=%d: payload stream error = %v", workers, payloadErr)
		}
		if metaErr == nil {
			t.Errorf("workers=%d: metadata stream completed despite payload failure", workers)
		}
	}
}

// Abandoning the streams mid-generation must not leak goroutines.
func TestGenerateV2CancellationNoLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)
	rng := rand.New(rand.NewSource(42))
	root := genTree(t, rng)

	for _, workers := range []int{1, 4} {
		a, err := archive.New(archive.Options{Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		metaRC, payloadRC, err := a.GenerateV2(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Read a little of each, then abandon.
		io.CopyN(io.Discard, payloadRC, 64)
		io.CopyN(io.Discard, metaRC, 64)
		cancel()
		metaRC.Close()
		payloadRC.Close()
	}
}

// The refs must match what pxar's size arithmetic promises: a fixed-size
// record, and offset/size fields the payload stream confirms. (The full
// cross-checks live in the parser; this pins the record constants the
// emitters rely on.)
func TestV2RecordSizes(t *testing.T) {
	if got := len(pxar.AppendPayloadRef(nil, 1, 2)); got != pxar.PayloadRefSize {
		t.Errorf("payload ref encodes to %d bytes, constant says %d", got, pxar.PayloadRefSize)
	}
	if got := len(pxar.AppendFormatVersion(nil, 2)); got != pxar.FormatVersionSize {
		t.Errorf("format version encodes to %d bytes, constant says %d", got, pxar.FormatVersionSize)
	}
	if got := len(pxar.AppendPayloadStartMarker(nil)); got != pxar.MarkerSize {
		t.Errorf("start marker encodes to %d bytes, constant says %d", got, pxar.MarkerSize)
	}
}
