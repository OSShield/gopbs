//go:build linux

package archive_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/scan"
	"go.uber.org/goleak"
)

// genTree writes a deterministic pseudo-random tree: nested dirs, files of
// mixed sizes (one crossing the 1 MiB chunk boundary), empty dirs, symlinks
// and hardlinks.
func genTree(t *testing.T, rng *rand.Rand) string {
	t.Helper()
	root := t.TempDir()

	var files []string
	var fill func(dir string, depth int)
	fill = func(dir string, depth int) {
		for i := 0; i < 1+rng.Intn(4); i++ {
			name := filepath.Join(dir, fmt.Sprintf("f%d.bin", i))
			data := make([]byte, rng.Intn(4096))
			rng.Read(data)
			if err := os.WriteFile(name, data, 0o644); err != nil {
				t.Fatal(err)
			}
			files = append(files, name)
		}
		if depth >= 3 {
			return
		}
		for i := 0; i < rng.Intn(3); i++ {
			sub := filepath.Join(dir, fmt.Sprintf("d%d", i))
			if err := os.Mkdir(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			fill(sub, depth+1)
		}
	}
	fill(root, 0)

	// One file spanning multiple read chunks.
	big := make([]byte, (1<<20)+rng.Intn(512<<10))
	rng.Read(big)
	if err := os.WriteFile(filepath.Join(root, "big.bin"), big, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(root, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("big.bin", filepath.Join(root, "s.link")); err != nil {
		t.Fatal(err)
	}
	if len(files) > 0 {
		target := files[rng.Intn(len(files))]
		if err := os.Link(target, filepath.Join(root, "z.hardlink")); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func generateWith(t *testing.T, root string, workers int, buffer int64, stream []byte) []byte {
	t.Helper()
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
	return generate(t, a)
}

// maskRootMtime zeroes the root entry's mtime field (bytes 40..52 of the
// stream): a virtual root's mtime is plan time by design, so two generations
// of the same tree legitimately differ there and nowhere else.
func maskRootMtime(data []byte) []byte {
	if len(data) >= 52 {
		clear(data[40:52])
	}
	return data
}

// Async output must be byte-identical to sync output across
// randomized trees, worker counts, and buffer budgets (including a tiny
// budget that forces head-of-line priority in the chunk pool).
func TestAsyncEqualsSync(t *testing.T) {
	if testing.Short() {
		t.Skip("randomized equality sweep")
	}
	for seed := int64(0); seed < 100; seed++ {
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
		syncOut := generateWith(t, root, 1, 0, nil)
		asyncOut := generateWith(t, root, workers, buffer, nil)
		_ = stream
		if !bytes.Equal(syncOut, asyncOut) {
			t.Fatalf("seed %d (workers=%d buffer=%d): async output differs from sync (%d vs %d bytes)",
				seed, workers, buffer, len(syncOut), len(asyncOut))
		}
		if seed%10 == 0 {
			if _, err := parseArchive(asyncOut); err != nil {
				t.Fatalf("seed %d: async archive does not parse: %v", seed, err)
			}
		}

		// Virtual-root archives with a stream: equal modulo the root's
		// plan-time mtime.
		if seed%5 == 0 {
			syncOut = maskRootMtime(generateWith(t, root, 1, 0, stream))
			asyncOut = maskRootMtime(generateWith(t, root, workers, buffer, append([]byte(nil), stream...)))
			if !bytes.Equal(syncOut, asyncOut) {
				t.Fatalf("seed %d: stream archive differs beyond the root mtime", seed)
			}
		}
	}
}

// Files changed between scan and dispatch: async late binding must emit the
// real bytes, identically to sync, without warnings.
func TestAsyncLateBindingRebindsSize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "changed.bin")
	content := bytes.Repeat([]byte("x"), 2000)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	inner, err := scan.DefaultReader()
	if err != nil {
		t.Fatal(err)
	}

	run := func(workers int) []byte {
		var warns []archive.Warning
		a, err := archive.New(archive.Options{
			Workers: workers,
			OnWarn:  func(w archive.Warning) { warns = append(warns, w) },
			Scan:    scan.Options{Reader: staleSizeReader{inner, path, -500}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		data := generate(t, a)
		if len(warns) != 0 {
			t.Fatalf("workers=%d: unexpected warnings %+v", workers, warns)
		}
		return data
	}

	syncOut, asyncOut := run(1), run(4)
	if !bytes.Equal(syncOut, asyncOut) {
		t.Fatal("sync and async differ under a stale scan size")
	}
	dec, err := parseArchive(asyncOut)
	if err != nil {
		t.Fatal(err)
	}
	if f := dec.find("changed.bin"); !bytes.Equal(f.content, content) {
		t.Errorf("content %d bytes, want %d", len(f.content), len(content))
	}
}

// Deterministic mid-read mutation coverage for both payload paths: the file
// changes between size binding and reading.
func TestPayloadMutationDetection(t *testing.T) {
	paths := map[string]func(n *scan.Node, mutate func()) (int64, []byte, []archive.Warning, error){
		"sync":  archive.SyncPayloadRun,
		"async": archive.AsyncPayloadRun,
	}
	for name, run := range paths {
		t.Run(name, func(t *testing.T) {
			node := func(content []byte) *scan.Node {
				dir := t.TempDir()
				p := filepath.Join(dir, "f")
				if err := os.WriteFile(p, content, 0o644); err != nil {
					t.Fatal(err)
				}
				s, err := scan.NewScanner(scan.Options{})
				if err != nil {
					t.Fatal(err)
				}
				n, err := s.ScanFile(p, "f")
				if err != nil {
					t.Fatal(err)
				}
				return n
			}

			t.Run("untouched", func(t *testing.T) {
				n := node([]byte("stable content"))
				size, data, warns, err := run(n, nil)
				if err != nil || size != 14 || string(data) != "stable content" || len(warns) != 0 {
					t.Fatalf("size=%d data=%q warns=%+v err=%v", size, data, warns, err)
				}
			})

			t.Run("shrunk", func(t *testing.T) {
				n := node(bytes.Repeat([]byte("a"), 100))
				size, data, warns, err := run(n, func() {
					if err := os.WriteFile(n.Path, []byte("short"), 0o644); err != nil {
						t.Fatal(err)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				want := append([]byte("short"), make([]byte, 95)...)
				if size != 100 || !bytes.Equal(data, want) {
					t.Fatalf("size=%d data=%q", size, data)
				}
				if !hasWarn(warns, archive.WarnSizeChanged) || !hasWarn(warns, archive.WarnTorn) {
					t.Fatalf("warns=%+v, want size-changed and torn", warns)
				}
			})

			t.Run("grown", func(t *testing.T) {
				n := node([]byte("0123456789"))
				grown := bytes.Repeat([]byte("Z"), 50)
				size, data, warns, err := run(n, func() {
					if err := os.WriteFile(n.Path, grown, 0o644); err != nil {
						t.Fatal(err)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				if size != 10 || !bytes.Equal(data, grown[:10]) {
					t.Fatalf("size=%d data=%q", size, data)
				}
				if hasWarn(warns, archive.WarnSizeChanged) || !hasWarn(warns, archive.WarnTorn) {
					t.Fatalf("warns=%+v, want torn only", warns)
				}
			})

			t.Run("same size touched", func(t *testing.T) {
				n := node([]byte("same-length A"))
				size, data, warns, err := run(n, func() {
					if err := os.WriteFile(n.Path, []byte("same-length B"), 0o644); err != nil {
						t.Fatal(err)
					}
					stamp := time.Now().Add(3 * time.Second)
					if err := os.Chtimes(n.Path, stamp, stamp); err != nil {
						t.Fatal(err)
					}
				})
				if err != nil || size != 13 || string(data) != "same-length B" {
					t.Fatalf("size=%d data=%q err=%v", size, data, err)
				}
				if hasWarn(warns, archive.WarnSizeChanged) || !hasWarn(warns, archive.WarnTorn) {
					t.Fatalf("warns=%+v, want torn only (the case pad/truncate alone misses)", warns)
				}
			})
		})
	}
}

func hasWarn(warns []archive.Warning, kind archive.WarnKind) bool {
	for _, w := range warns {
		if w.Kind == kind {
			return true
		}
	}
	return false
}

// Abandoning generation must tear down the dispatcher, workers and emitter
// without leaking goroutines, whether via reader Close or context cancel.
func TestAsyncCancellationNoLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	root := t.TempDir()
	for i := 0; i < 40; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%02d", i)), bytes.Repeat([]byte{byte(i)}, 200_000), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	newArchive := func() *archive.Archive {
		a, err := archive.New(archive.Options{Workers: 4, Buffer: 1}) // minimal budget: most goroutines parked
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		return a
	}

	t.Run("reader close", func(t *testing.T) {
		rc, err := newArchive().GenerateV1(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(rc, make([]byte, 64<<10)); err != nil {
			t.Fatal(err)
		}
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("context cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		rc, err := newArchive().GenerateV1(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		if _, err := io.ReadFull(rc, make([]byte, 64<<10)); err != nil {
			t.Fatal(err)
		}
		cancel()
		if _, err := io.Copy(io.Discard, rc); err == nil {
			t.Error("reads after cancel must fail")
		}
	})

	// Completed generation must also leave nothing behind.
	t.Run("run to completion", func(t *testing.T) {
		rc, err := newArchive().GenerateV1(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
	})
}

func benchTree(b *testing.B, files, size int) string {
	b.Helper()
	root := b.TempDir()
	data := make([]byte, size)
	rand.New(rand.NewSource(1)).Read(data)
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%04d", i)), data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	return root
}

func benchGenerate(b *testing.B, root string, workers int) {
	b.Helper()
	for i := 0; i < b.N; i++ {
		a, err := archive.New(archive.Options{Workers: workers})
		if err != nil {
			b.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			b.Fatal(err)
		}
		rc, err := a.GenerateV1(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		n, err := io.Copy(io.Discard, rc)
		if err != nil {
			b.Fatal(err)
		}
		rc.Close()
		b.SetBytes(n)
	}
}

func BenchmarkGenerateManySmall(b *testing.B) {
	root := benchTree(b, 2000, 8<<10)
	b.Run("sync", func(b *testing.B) { benchGenerate(b, root, 1) })
	b.Run("async", func(b *testing.B) { benchGenerate(b, root, 0) })
}

func BenchmarkGenerateFewLarge(b *testing.B) {
	root := benchTree(b, 8, 32<<20)
	b.Run("sync", func(b *testing.B) { benchGenerate(b, root, 1) })
	b.Run("async", func(b *testing.B) { benchGenerate(b, root, 0) })
}
