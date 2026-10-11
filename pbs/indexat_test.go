package pbs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pbs/pbstest"
)

func openAt(t *testing.T, c *pbs.Client, ref pbs.SnapshotRef, ctx context.Context) *pbs.IndexFile {
	t.Helper()
	f, err := startReader(t, c, ref).OpenDynamicIndexAt(ctx, "data.db")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestIndexFileReadAt(t *testing.T) {
	data := append(randomBytes(900_000), bytes.Repeat([]byte("repeated tail "), 20_000)...)
	key := testKey(t)
	for _, tc := range []struct {
		name  string
		crypt *pbs.CryptConfig
	}{
		{"none", nil},
		{"encrypt", &pbs.CryptConfig{Mode: pbs.CryptModeEncrypt, Key: key}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := pbstest.NewServer(t)
			m.SetCryptKey(key)
			c := clientFor(t, m, func(c *pbs.Config) { c.Crypt = tc.crypt; c.ChunkSizeAvg = 64 << 10 })
			ref, stats := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, data, []byte("{}"))
			f := openAt(t, c, ref, context.Background())
			size := int64(len(data))
			if f.Size() != size {
				t.Fatalf("Size = %d, want %d", f.Size(), size)
			}

			boundary := int64(stats.Entries[0].EndOffset)
			for _, r := range []struct {
				off  int64
				n    int
				want int
				eof  bool
			}{
				{0, 10, 10, false},
				{boundary - 5, 10, 10, false}, // spans two chunks
				{0, int(size), int(size), false},
				{size - 3, 10, 3, true},
				{size, 1, 0, true},
				{size + 100, 1, 0, true},
			} {
				buf := make([]byte, r.n)
				n, err := f.ReadAt(buf, r.off)
				if n != r.want || (err == io.EOF) != r.eof || (err != nil && err != io.EOF) {
					t.Fatalf("ReadAt(%d, %d) = %d, %v; want %d, eof %v", r.off, r.n, n, err, r.want, r.eof)
				}
				if !bytes.Equal(buf[:n], data[r.off:r.off+int64(n)]) {
					t.Fatalf("ReadAt(%d, %d): content differs", r.off, r.n)
				}
			}
			got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("sequential read: %d bytes, %v", len(got), err)
			}
		})
	}
}

func TestIndexFileConcurrent(t *testing.T) {
	m := pbstest.NewServer(t)
	c := clientFor(t, m, func(c *pbs.Config) { c.ChunkSizeAvg = 64 << 10 })
	data := randomBytes(1_500_000)
	ref, _ := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, data, []byte("{}"))

	// Simultaneous reads of one chunk download it once. The last chunk
	// has nothing after it to read ahead.
	f := openAt(t, c, ref, context.Background())
	m.Lock()
	before := m.ChunkDownloads
	m.Unlock()
	off := int64(len(data)) - 100
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			buf := make([]byte, 100)
			if _, err := f.ReadAt(buf, off); err != nil || !bytes.Equal(buf, data[off:]) {
				t.Errorf("concurrent same-chunk read: %v", err)
			}
		})
	}
	wg.Wait()
	m.Lock()
	if d := m.ChunkDownloads - before; d != 1 {
		t.Errorf("same chunk downloaded %d times", d)
	}
	m.Unlock()

	// Random reads across the whole index, beyond the cache size.
	for g := range 16 {
		wg.Go(func() {
			rng := rand.New(rand.NewSource(int64(g)))
			for range 50 {
				off := rng.Int63n(int64(len(data)))
				buf := make([]byte, rng.Intn(200_000))
				n, err := f.ReadAt(buf, off)
				if (err != nil && err != io.EOF) || !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
					t.Errorf("ReadAt(%d, %d): %d, %v", off, len(buf), n, err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestIndexFileTampered(t *testing.T) {
	m := pbstest.NewServer(t)
	c := clientFor(t, m, func(c *pbs.Config) { c.ChunkSizeAvg = 64 << 10 })
	ref, stats := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(400_000), []byte("{}"))
	m.Lock()
	framed := m.ChunksEncoded[hexDigest(stats.Entries[1].Digest)]
	framed[len(framed)-1] ^= 0xff
	fixCRC(framed)
	m.Unlock()

	f := openAt(t, c, ref, context.Background())
	if _, err := f.ReadAt(make([]byte, 10), 0); err != nil {
		t.Fatalf("intact chunk: %v", err)
	}
	_, err := f.ReadAt(make([]byte, 10), int64(stats.Entries[1].EndOffset)-5)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered chunk: %v", err)
	}
}

func TestIndexFileCancel(t *testing.T) {
	m := pbstest.NewServer(t)
	c := clientFor(t, m, nil)
	ref, _ := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(10_000), []byte("{}"))
	ctx, cancel := context.WithCancel(context.Background())
	f := openAt(t, c, ref, ctx)
	cancel()
	if _, err := f.ReadAt(make([]byte, 10), 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// A sequential read keeps downloads in flight, so it beats fetching one
// chunk at a time, and still downloads every chunk exactly once.
func TestIndexFileReadAhead(t *testing.T) {
	m := pbstest.NewServer(t)
	c := clientFor(t, m, func(c *pbs.Config) { c.ChunkSizeAvg = 64 << 10; c.Workers = 4 })
	data := randomBytes(1_000_000)
	ref, stats := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, data, []byte("{}"))
	const delay = 30 * time.Millisecond
	m.Lock()
	m.DownloadDelay = func(string) time.Duration { return delay }
	before := m.ChunkDownloads
	m.Unlock()

	f := openAt(t, c, ref, context.Background())
	start := time.Now()
	got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	elapsed := time.Since(start)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("sequential read: %v", err)
	}
	if serial := time.Duration(stats.ChunkCount) * delay; elapsed > serial*6/10 {
		t.Fatalf("sequential read of %d chunks took %v; one at a time takes %v", stats.ChunkCount, elapsed, serial)
	}
	time.Sleep(2 * delay) // let stray prefetches land
	m.Lock()
	defer m.Unlock()
	if d := m.ChunkDownloads - before; d != int(stats.ChunkCount) {
		t.Fatalf("%d downloads for %d chunks", d, stats.ChunkCount)
	}
}
