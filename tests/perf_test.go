//go:build integration

package main_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	gopbs "github.com/scheiblingco/gopbs"
	"github.com/scheiblingco/gopbs/archive"
	"github.com/scheiblingco/gopbs/pbs"
)

// TestPerformance compares archive generation and upload throughput across
// implementations and modes:
//
//   - generation to file: gopbs v1 sync, v1 async, v2 async, and the official
//     pxar CLI (v1 and v2 split);
//   - upload to the pmoxs3+garage stack: gopbs.Backup (v1 and v2) and the
//     official proxmox-backup-client (legacy and metadata change-detection),
//     each as a fresh backup and again as a fully-deduplicated second run.
//
// It is skipped unless GOPBS_PERF=1 — it generates a sizable tree
// (GOPBS_PERF_MB, default 512) and takes minutes. Container-based runs carry
// ~1s of docker startup overhead; treat the numbers as indicative, not as a
// microbenchmark.
//
//	GOPBS_PERF=1 GOPBS_PERF_MB=512 go test -tags integration -run TestPerformance -v .
func TestPerformance(t *testing.T) {
	if os.Getenv("GOPBS_PERF") == "" {
		t.Skip("set GOPBS_PERF=1 (optionally GOPBS_PERF_MB=512) to run the performance comparison")
	}
	totalMB := 512
	if s := os.Getenv("GOPBS_PERF_MB"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 16 {
			t.Fatalf("GOPBS_PERF_MB=%q: want an integer >= 16", s)
		}
		totalMB = v
	}

	perfDir := filepath.Join(sourceDir, "perf")
	buildPerfTree(t, perfDir, totalMB)
	total := float64(treeSize(t, perfDir))
	t.Logf("tree: %d MB target, %.1f MiB actual, in %s", totalMB, total/(1<<20), perfDir)

	type row struct {
		name    string
		seconds float64
	}
	var results []row
	timed := func(name string, f func() error) {
		t.Helper()
		start := time.Now()
		if err := f(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		secs := time.Since(start).Seconds()
		results = append(results, row{name, secs})
		t.Logf("%-42s %7.2fs  %8.1f MiB/s", name, secs, total/(1<<20)/secs)
	}

	// --- Generation to file ---------------------------------------------

	genV1 := func(workers int, out string) func() error {
		return func() error {
			a, err := archive.New(archive.Options{Workers: workers})
			if err != nil {
				return err
			}
			if err := a.AddDirectory(perfDir); err != nil {
				return err
			}
			stream, err := a.GenerateV1(context.Background())
			if err != nil {
				return err
			}
			defer stream.Close()
			return writeTo(out, stream)
		}
	}
	timed("generate v1 gopbs sync (workers=1)", genV1(1, filepath.Join(pxarDir, "perf-sync.pxar")))
	timed(fmt.Sprintf("generate v1 gopbs async (workers=%d)", runtime.GOMAXPROCS(0)),
		genV1(0, filepath.Join(pxarDir, "perf-async.pxar")))
	timed("generate v1 official pxar (docker)", func() error {
		return compose("run", "--rm", "--remove-orphans", "pbs",
			"create", "/pxar/perf-official.pxar", "/source/perf")
	})

	timed("generate v2 gopbs async", func() error {
		a, err := archive.New(archive.Options{})
		if err != nil {
			return err
		}
		if err := a.AddDirectory(perfDir); err != nil {
			return err
		}
		meta, payload, err := a.GenerateV2(context.Background())
		if err != nil {
			return err
		}
		defer meta.Close()
		defer payload.Close()
		var wg sync.WaitGroup
		var payloadErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			payloadErr = writeTo(filepath.Join(pxarDir, "perf.ppxar"), payload)
		}()
		metaErr := writeTo(filepath.Join(pxarDir, "perf.mpxar"), meta)
		wg.Wait()
		if metaErr != nil {
			return metaErr
		}
		return payloadErr
	})
	timed("generate v2 official pxar (docker)", func() error {
		return compose("run", "--rm", "--remove-orphans", "pbs",
			"create", "/pxar/perf-official.mpxar", "/source/perf",
			"--payload-output", "/pxar/perf-official.ppxar")
	})

	// Sanity: same bytes as the official tool (single-dir root, so exact).
	for _, pair := range [][2]string{
		{"perf-async.pxar", "perf-official.pxar"},
		{"perf.mpxar", "perf-official.mpxar"},
		{"perf.ppxar", "perf-official.ppxar"},
	} {
		if !filesEqual(t, filepath.Join(pxarDir, pair[0]), filepath.Join(pxarDir, pair[1])) {
			t.Errorf("%s differs from %s", pair[0], pair[1])
		}
	}

	// --- Upload to the pmoxs3 stack --------------------------------------

	startPBSStack(t)
	cfg := pbs.Config{
		BaseURL:     pmoxURL,
		Auth:        pbs.PasswordAuth{Username: pmoxUser, Realm: pmoxRealm, Password: pmoxSecret},
		Fingerprint: pmoxFingerprint,
		Datastore:   pmoxDatastore,
	}
	// Wait for the stack (same retry the orchestrator tests use).
	client, err := pbs.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startSession(t, client, pbs.SnapshotRef{Type: "host", ID: "perf-warmup"}).Abort()

	stamp := time.Now().UnixNano()
	gopbsUpload := func(format gopbs.Format, id string) func() error {
		return func() error {
			_, err := gopbs.Backup(context.Background(), gopbs.BackupOptions{
				Client:  cfg,
				Archive: archive.Options{Name: "root"},
				Ref:     pbs.SnapshotRef{Type: "host", ID: id},
				Format:  format,
				Paths:   []string{perfDir},
			})
			return err
		}
	}
	officialUpload := func(mode, id string) func() error {
		return func() error {
			return compose("run", "--rm", "--remove-orphans",
				"-e", "SUBDIR=perf", "-e", "BACKUPID="+id, "-e", "MODE="+mode,
				"pbsbackup")
		}
	}

	for _, up := range []struct {
		name string
		id   string
		run  func() error
	}{
		{"upload v1 gopbs", fmt.Sprintf("perf-gopbs-v1-%d", stamp), gopbsUpload(gopbs.FormatV1, fmt.Sprintf("perf-gopbs-v1-%d", stamp))},
		{"upload v2 gopbs", fmt.Sprintf("perf-gopbs-v2-%d", stamp), gopbsUpload(gopbs.FormatV2, fmt.Sprintf("perf-gopbs-v2-%d", stamp))},
		{"upload v1 official client (docker)", fmt.Sprintf("perf-official-v1-%d", stamp), officialUpload("legacy", fmt.Sprintf("perf-official-v1-%d", stamp))},
		{"upload v2 official client (docker)", fmt.Sprintf("perf-official-v2-%d", stamp), officialUpload("metadata", fmt.Sprintf("perf-official-v2-%d", stamp))},
	} {
		timed(up.name+" (fresh)", up.run)
		time.Sleep(2 * time.Second) // pmoxs3 resolves "previous" at seconds granularity
		timed(up.name+" (dedup rerun)", up.run)
	}

	t.Log("---- summary ----")
	for _, r := range results {
		t.Logf("%-42s %7.2fs  %8.1f MiB/s", r.name, r.seconds, total/(1<<20)/r.seconds)
	}
}

// buildPerfTree writes a deterministic mixed tree of roughly totalMB MiB:
// 50% incompressible random data, 25% compressible text, split across many
// small files, medium files and a few large ones — the shapes that stress
// per-entry overhead, pipelining and raw throughput respectively.
func buildPerfTree(t *testing.T, dir string, totalMB int) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	text := []byte("The quick brown fox jumps over the lazy dog; pack my box with five dozen liquor jugs.\n")

	write := func(path string, size int, compressible bool) {
		buf := make([]byte, size)
		if compressible {
			for i := 0; i < size; i += len(text) {
				copy(buf[i:], text)
			}
		} else {
			rng.Read(buf)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	total := totalMB << 20
	// Large: half the budget in 64 MiB random files.
	for i, remaining := 0, total/2; remaining > 0; i++ {
		size := 64 << 20
		if size > remaining {
			size = remaining
		}
		write(filepath.Join(dir, "large", fmt.Sprintf("blob_%02d.bin", i)), size, false)
		remaining -= size
	}
	// Medium: a quarter in 1 MiB text files.
	for i, remaining := 0, total/4; remaining > 0; i++ {
		size := 1 << 20
		if size > remaining {
			size = remaining
		}
		write(filepath.Join(dir, "medium", fmt.Sprintf("doc_%03d.txt", i)), size, true)
		remaining -= size
	}
	// Small: the rest in 16 KiB random files, 256 per directory.
	for i, remaining := 0, total/4; remaining > 0; i++ {
		size := 16 << 10
		if size > remaining {
			size = remaining
		}
		write(filepath.Join(dir, "small", fmt.Sprintf("d%02d", i/256), fmt.Sprintf("f%05d.bin", i)), size, false)
		remaining -= size
	}
}

func treeSize(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return total
}

func writeTo(path string, r io.Reader) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func filesEqual(t *testing.T, a, b string) bool {
	t.Helper()
	hash := func(path string) [sha256.Size]byte {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			t.Fatal(err)
		}
		var sum [sha256.Size]byte
		copy(sum[:], h.Sum(nil))
		return sum
	}
	return hash(a) == hash(b)
}
