package gopbs_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pbs/pbstest"
)

// BenchmarkRestore measures restores from the mock server with a simulated
// per-chunk download latency: full restores (v1 streams its one index,
// v2 reads the payload by random access), a one-file selective restore and
// Browse. Reported per operation: MB/s of archive content and chunks
// downloaded.
func BenchmarkRestore(b *testing.B) {
	src := b.TempDir()
	rng := rand.New(rand.NewSource(1))
	const files, size = 32, 2 << 20
	for i := range files {
		data := make([]byte, size)
		rng.Read(data)
		dir := filepath.Join(src, fmt.Sprintf("d%d", i%4))
		os.MkdirAll(dir, 0o755)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.bin", i)), data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	ctx := context.Background()

	for _, format := range []gopbs.Format{gopbs.FormatV1, gopbs.FormatV2} {
		m := pbstest.NewServer(b)
		cfg := pbs.Config{
			BaseURL:      m.URL,
			Auth:         pbs.TokenAuth{AuthID: "user@pam!token", Secret: "s3cret"},
			Fingerprint:  m.Fingerprint,
			Datastore:    "store1",
			ChunkSizeAvg: 1 << 20,
		}
		_, err := gopbs.Backup(ctx, gopbs.BackupOptions{
			Client: cfg, Archive: archive.Options{Name: "root"}, Format: format,
			Ref: pbs.SnapshotRef{ID: "bench", Time: time.Unix(1_700_000_000, 0)}, Paths: []string{src},
		})
		if err != nil {
			b.Fatal(err)
		}
		opts := gopbs.RestoreOptions{Client: cfg, Ref: pbs.SnapshotRef{ID: "bench"}, Archive: "root"}

		for _, latency := range []time.Duration{0, 5 * time.Millisecond, 20 * time.Millisecond} {
			m.Lock()
			m.DownloadDelay = func(string) time.Duration { return latency }
			m.Unlock()
			name := fmt.Sprintf("v%d/latency=%v", int(format)+1, latency)
			run := func(b *testing.B, bytes int64, op func(dst string) error) {
				b.SetBytes(bytes)
				m.Lock()
				before := m.ChunkDownloads
				m.Unlock()
				for b.Loop() {
					dst := filepath.Join(b.TempDir(), "out")
					if err := op(dst); err != nil {
						b.Fatal(err)
					}
					b.StopTimer()
					os.RemoveAll(dst)
					b.StartTimer()
				}
				m.Lock()
				b.ReportMetric(float64(m.ChunkDownloads-before)/float64(b.N), "chunks/op")
				m.Unlock()
			}

			b.Run(name+"/full", func(b *testing.B) {
				run(b, files*size, func(dst string) error {
					o := opts
					o.Target = dst
					_, err := gopbs.Restore(ctx, o)
					return err
				})
			})
			b.Run(name+"/one-file", func(b *testing.B) {
				run(b, size, func(dst string) error {
					o := opts
					o.Target, o.Paths = dst, []string{"d3/f31.bin"}
					_, err := gopbs.Restore(ctx, o)
					return err
				})
			})
			b.Run(name+"/browse", func(b *testing.B) {
				run(b, 0, func(string) error {
					sess, err := gopbs.OpenSnapshot(ctx, cfg, opts.Ref, nil)
					if err != nil {
						return err
					}
					defer sess.Close()
					_, err = gopbs.Browse(ctx, sess, "root")
					return err
				})
			})
		}
	}
}
