package gopbs_test

import (
	"bytes"
	"context"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pbs/pbstest"
	"github.com/osshield/gopbs/pxar"
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
