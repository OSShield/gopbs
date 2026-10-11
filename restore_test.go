package gopbs_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/catalog"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pbs/pbstest"
	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/restore"
)

// A backup reads back as a file system over remote random access: the
// reader session's IndexFile feeding pxar.OpenV1 / OpenV2.
func TestBackupReadsBackAsFS(t *testing.T) {
	src := t.TempDir()
	big := make([]byte, 2<<20)
	rand.New(rand.NewSource(1)).Read(big)
	for name, data := range map[string][]byte{
		"big.bin": big, "a.txt": []byte("alpha"), "d/b.txt": []byte("beta"), "d/e/empty": nil,
	} {
		path := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := pbstest.NewServer(t)
	cfg := pbs.Config{
		BaseURL:      m.URL,
		Auth:         pbs.TokenAuth{AuthID: "user@pam!token", Secret: "s3cret"},
		Fingerprint:  m.Fingerprint,
		Datastore:    "store1",
		ChunkSizeAvg: 64 << 10,
	}
	client, err := pbs.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	for i, format := range []gopbs.Format{gopbs.FormatV1, gopbs.FormatV2} {
		res, err := gopbs.Backup(ctx, gopbs.BackupOptions{
			Client: cfg,
			Ref:    pbs.SnapshotRef{ID: "e2e", Time: time.Unix(1_700_000_000+int64(i), 0)},
			Format: format,
			Paths:  []string{src},
		})
		if err != nil {
			t.Fatal(err)
		}
		r, err := client.StartReader(ctx, res.Ref)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()

		meta, err := r.OpenDynamicIndexAt(ctx, res.ArchiveName)
		if err != nil {
			t.Fatal(err)
		}
		var fsys *pxar.FS
		if format == gopbs.FormatV1 {
			fsys, err = pxar.OpenV1(meta, meta.Size())
		} else {
			payload, perr := r.OpenDynamicIndexAt(ctx, strings.Replace(res.ArchiveName, ".mpxar", ".ppxar", 1))
			if perr != nil {
				t.Fatal(perr)
			}
			fsys, err = pxar.OpenV2(meta, meta.Size(), payload)
		}
		if err != nil {
			t.Fatal(err)
		}

		if err := fstest.TestFS(fsys, "big.bin", "a.txt", "d/b.txt", "d/e/empty"); err != nil {
			t.Fatalf("%s: %v", res.ArchiveName, err)
		}
		got, err := fs.ReadFile(fsys, "big.bin")
		if err != nil || !bytes.Equal(got, big) {
			t.Fatalf("%s: big.bin differs: %v", res.ArchiveName, err)
		}
	}
}

// writeTree writes a small tree with fixed mtimes and returns its path.
func writeTree(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	big := make([]byte, 1<<20)
	rand.New(rand.NewSource(2)).Read(big)
	for i, f := range []struct {
		name string
		data []byte
	}{{"big.bin", big}, {"a.txt", []byte("alpha")}, {"d/b.txt", []byte("beta")}, {"d/e/c.txt", nil}} {
		p := filepath.Join(src, f.name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, f.data, 0o640); err != nil {
			t.Fatal(err)
		}
		when := time.Unix(1_650_000_000+int64(i), 123_000_000)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	return src
}

// sameFiles checks that every regular file under want exists under got
// with the same content and mtime.
func sameFiles(t *testing.T, want, got string, only ...string) {
	t.Helper()
	err := filepath.WalkDir(want, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(want, p)
		if len(only) > 0 && !slices.ContainsFunc(only, func(o string) bool { return strings.HasPrefix(filepath.ToSlash(rel), o) }) {
			if _, err := os.Lstat(filepath.Join(got, rel)); err == nil {
				t.Errorf("%s restored but not selected", rel)
			}
			return nil
		}
		a, _ := os.ReadFile(p)
		b, err := os.ReadFile(filepath.Join(got, rel))
		if err != nil || !bytes.Equal(a, b) {
			t.Errorf("%s: content differs (%v)", rel, err)
			return nil
		}
		ai, _ := os.Stat(p)
		bi, _ := os.Stat(filepath.Join(got, rel))
		if !ai.ModTime().Equal(bi.ModTime()) {
			t.Errorf("%s: mtime %v, want %v", rel, bi.ModTime(), ai.ModTime())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRestore(t *testing.T) {
	src := writeTree(t)
	pub, err := os.ReadFile("pbs/testdata/master-public.pem")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := os.ReadFile("pbs/testdata/master-private.pem")
	master, err := pbs.LoadMasterKey(priv, []byte("masterpass"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := pbs.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []gopbs.Format{gopbs.FormatV1, gopbs.FormatV2} {
		t.Run(fmt.Sprint("v", int(format)+1), func(t *testing.T) {
			m := pbstest.NewServer(t)
			m.SetCryptKey(key)
			cfg := pbs.Config{
				BaseURL:      m.URL,
				Auth:         pbs.TokenAuth{AuthID: "user@pam!token", Secret: "s3cret"},
				Fingerprint:  m.Fingerprint,
				Datastore:    "store1",
				ChunkSizeAvg: 64 << 10,
			}
			ctx := context.Background()
			backup := cfg
			backup.Crypt = &pbs.CryptConfig{Key: key, MasterPublicKey: pub}
			for i := range 2 { // the restore must pick the newer one
				_, err := gopbs.Backup(ctx, gopbs.BackupOptions{
					Client:  backup,
					Archive: archive.Options{Name: "root"},
					Ref:     pbs.SnapshotRef{ID: "host1", Time: time.Unix(1_700_000_000+int64(i), 0)},
					Format:  format,
					Paths:   []string{src},
				})
				if err != nil {
					t.Fatal(err)
				}
			}

			// Full restore with only the master key at hand.
			dst := t.TempDir()
			res, err := gopbs.Restore(ctx, gopbs.RestoreOptions{
				Client: cfg, MasterKey: master, Ref: pbs.SnapshotRef{ID: "host1"},
				Archive: "root", Target: dst,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Format != format || res.Ref.Time.Unix() != 1_700_000_001 || len(res.Warnings) > 0 {
				t.Fatalf("result %+v", res)
			}
			sameFiles(t, src, dst)

			// Selective restore, by key.
			withKey := cfg
			withKey.Crypt = &pbs.CryptConfig{Key: key}
			dst = t.TempDir()
			_, err = gopbs.Restore(ctx, gopbs.RestoreOptions{
				Client: withKey, Ref: pbs.SnapshotRef{ID: "host1"}, Archive: "root.pxar",
				Target: dst, Paths: []string{"d/e", "a.txt"},
			})
			if err != nil {
				t.Fatal(err)
			}
			sameFiles(t, src, dst, "d/e", "a.txt")

			_, err = gopbs.Restore(ctx, gopbs.RestoreOptions{Client: withKey, Ref: pbs.SnapshotRef{ID: "host1"}, Archive: "root", Target: dst})
			if !errors.Is(err, restore.ErrTargetNotEmpty) {
				t.Fatalf("non-empty target: %v", err)
			}
			_, err = gopbs.Restore(ctx, gopbs.RestoreOptions{Client: withKey, Ref: pbs.SnapshotRef{ID: "host1"}, Archive: "other", Target: t.TempDir()})
			if !errors.Is(err, pbs.ErrNotFound) {
				t.Fatalf("unknown archive: %v", err)
			}

			sess, err := gopbs.OpenSnapshot(ctx, withKey, pbs.SnapshotRef{ID: "host1"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			tree, err := gopbs.Browse(ctx, sess, "root")
			if err != nil {
				t.Fatal(err)
			}
			d := tree.Child("d")
			if d == nil || d.Type != catalog.TypeDirectory || d.Child("b.txt") == nil || d.Child("b.txt").Size != 4 ||
				tree.Child("big.bin") == nil || tree.Child("big.bin").MtimeSecs != 1_650_000_000 {
				t.Fatalf("browse: %+v", tree)
			}
		})
	}
}
