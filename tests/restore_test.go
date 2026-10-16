//go:build integration

package main_test

import (
	"context"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/pbs"
)

// gopbs restores backups the official client made, v1 and v2, encrypted
// with a key gopbs never sees: it recovers the key from the snapshot's
// master-key wrapped copy (the official client's wrapping), then restores
// the tree with content, modes, mtimes, symlinks and hardlinks intact.
func TestRestoreOfficialBackups(t *testing.T) {
	startPBSStack(t)

	src := filepath.Join(sourceDir, "restore")
	writeRestoreTree(t, src)
	key, err := pbs.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := pbs.CreateKeyFile(key, nil, pbs.KDFNone, "")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile("../pbs/testdata/master-public.pem")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := os.ReadFile("../pbs/testdata/master-private.pem")
	if err != nil {
		t.Fatal(err)
	}
	master, err := pbs.LoadMasterKey(priv, []byte("masterpass"))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"restore-key.json": keyJSON, "master-public.pem": pub} {
		if err := os.WriteFile(filepath.Join(keysDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := pbs.Config{
		BaseURL:     pmoxURL,
		Auth:        pbs.PasswordAuth{Username: pmoxUser, Realm: pmoxRealm, Password: pmoxSecret},
		Fingerprint: pmoxFingerprint,
		Datastore:   pmoxDatastore,
	}
	client, err := pbs.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startSession(t, client, pbs.SnapshotRef{ID: "restore-ready"}).Abort()

	for _, mode := range []string{"legacy", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			id := fmt.Sprintf("restore-%s-%d", mode, time.Now().UnixNano())
			err := compose("run", "--rm", "--remove-orphans",
				"-e", "SUBDIR=restore", "-e", "BACKUPID="+id, "-e", "MODE="+mode,
				"-e", "KEYFILE=/keys/restore-key.json", "-e", "MASTERPUB=/keys/master-public.pem",
				"pbsbackup")
			if err != nil {
				t.Fatal(err)
			}
			dst := t.TempDir()
			res, err := gopbs.Restore(context.Background(), gopbs.RestoreOptions{
				Client: cfg, MasterKey: master, Ref: pbs.SnapshotRef{ID: id}, Archive: "root", Target: dst,
			})
			if err != nil {
				t.Fatal(err)
			}
			if want := map[string]gopbs.Format{"legacy": gopbs.FormatV1, "metadata": gopbs.FormatV2}[mode]; res.Format != want {
				t.Fatalf("format %v, want %v", res.Format, want)
			}
			for _, w := range res.Warnings {
				t.Errorf("warning: %v", w)
			}
			sameTree(t, src, dst)
		})
	}
}

func writeRestoreTree(t *testing.T, src string) {
	t.Helper()
	// src lives under sourceDir (compose mounts it), which TestComparison and
	// TestPBS compare against: don't leave it behind for them.
	t.Cleanup(func() { os.RemoveAll(src) })
	rng := rand.New(rand.NewSource(7))
	for i := range 20 {
		dir := filepath.Join(src, fmt.Sprintf("d%d", i%4), fmt.Sprintf("s%d", i%3))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, rng.Intn(3<<20))
		rng.Read(data)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.bin", i)), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("d0/s0/f0.bin", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(src, "d1/s1/f1.bin"), filepath.Join(src, "hard")); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Type()&fs.ModeSymlink == 0 {
			when := time.Unix(1_650_000_000+rng.Int63n(1e6), rng.Int63n(1e9))
			os.Chtimes(p, when, when)
		}
		return err
	})
}

// sameTree compares type, permissions, mtime (files), symlink targets and
// content of every entry, and that "hard" is still a hardlink.
func sameTree(t *testing.T, want, got string) {
	t.Helper()
	var n int
	err := filepath.WalkDir(want, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n++
		rel, _ := filepath.Rel(want, p)
		a, _ := os.Lstat(p)
		b, err := os.Lstat(filepath.Join(got, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			return nil
		}
		if a.Mode() != b.Mode() || (a.Mode().IsRegular() && !a.ModTime().Equal(b.ModTime())) {
			t.Errorf("%s: %v %v, restored %v %v", rel, a.Mode(), a.ModTime(), b.Mode(), b.ModTime())
		}
		switch {
		case a.Mode()&fs.ModeSymlink != 0:
			x, _ := os.Readlink(p)
			y, _ := os.Readlink(filepath.Join(got, rel))
			if x != y {
				t.Errorf("%s: link %q, restored %q", rel, y, x)
			}
		case a.Mode().IsRegular():
			x, _ := os.ReadFile(p)
			y, _ := os.ReadFile(filepath.Join(got, rel))
			if string(x) != string(y) {
				t.Errorf("%s: content differs", rel)
			}
		}
		return nil
	})
	if err != nil || n < 20 {
		t.Fatalf("walked %d entries: %v", n, err)
	}
	a, _ := os.Stat(filepath.Join(got, "hard"))
	b, _ := os.Stat(filepath.Join(got, "d1/s1/f1.bin"))
	if !os.SameFile(a, b) {
		t.Error("hardlink restored as a copy")
	}
}
