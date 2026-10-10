//go:build linux

package archive_test

import (
	"bytes"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pxar"
)

// pxar.Reader must agree with the structural test parser (an independent
// decoder that also verifies every goodbye table) on generated archives.
func TestPxarReaderMatchesParser(t *testing.T) {
	for seed := int64(0); seed < 10; seed++ {
		rng := rand.New(rand.NewSource(seed))
		root := genTree(t, rng)
		stream := make([]byte, rng.Intn(100_000))
		rng.Read(stream)

		v1 := generateWith(t, root, 4, 0, stream)
		want, err := parseArchive(v1)
		if err != nil {
			t.Fatal(err)
		}
		compareReader(t, pxar.NewReaderV1(bytes.NewReader(v1)), want)

		a, err := archive.New(archive.Options{Name: "eq", Workers: 4})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		meta, payload := generateV2(t, a)
		if want, err = parseArchiveV2(meta, payload); err != nil {
			t.Fatal(err)
		}
		compareReader(t, pxar.NewReaderV2(bytes.NewReader(meta), bytes.NewReader(payload)), want)
	}
}

func compareReader(t *testing.T, r *pxar.Reader, root *decNode) {
	t.Helper()
	var walk func(n *decNode, path string)
	walk = func(n *decNode, path string) {
		got, err := r.Next()
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		if got.Path != path {
			t.Fatalf("path %q, want %q", got.Path, path)
		}
		if n.hardlink.target != "" {
			if !got.Hardlink || got.LinkTarget != n.hardlink.target {
				t.Fatalf("%q: hardlink %v %q, want %q", path, got.Hardlink, got.LinkTarget, n.hardlink.target)
			}
			return
		}
		e := pxar.Entry{Mode: n.mode, UID: n.uid, GID: n.gid, MtimeSecs: n.mtimeSecs, MtimeNanos: n.mtimeNanos}
		if got.Entry != e || got.LinkTarget != n.symlink || got.Device != n.device {
			t.Fatalf("%q: decoded %+v, want entry %+v symlink %q device %v", path, got, e, n.symlink, n.device)
		}
		if !slices.EqualFunc(got.Xattrs, n.xattrs, func(a, b pxar.Xattr) bool {
			return a.Name == b.Name && bytes.Equal(a.Value, b.Value)
		}) {
			t.Fatalf("%q: xattrs %v, want %v", path, got.Xattrs, n.xattrs)
		}
		content, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		if !bytes.Equal(content, n.content) || got.Size != uint64(len(n.content)) {
			t.Fatalf("%q: content differs (%d bytes, size %d, want %d)", path, len(content), got.Size, len(n.content))
		}
		for _, c := range n.children {
			if path == "" {
				walk(c, c.name)
			} else {
				walk(c, path+"/"+c.name)
			}
		}
	}
	walk(root, "")
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("after the last entry: %v, want io.EOF", err)
	}
}

// Generated archives opened as file systems match the source tree.
func TestPxarFSMatchesTree(t *testing.T) {
	for seed := int64(0); seed < 5; seed++ {
		root := genTree(t, rand.New(rand.NewSource(seed)))
		v1 := generateWith(t, root, 4, 0, nil)
		a, err := archive.New(archive.Options{Name: "fs", Workers: 4})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		meta, payload := generateV2(t, a)

		v1fs, err := pxar.OpenV1(bytes.NewReader(v1), int64(len(v1)))
		if err != nil {
			t.Fatal(err)
		}
		v2fs, err := pxar.OpenV2(bytes.NewReader(meta), int64(len(meta)), bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		for _, fsys := range []*pxar.FS{v1fs, v2fs} {
			var files []string
			err := fs.WalkDir(os.DirFS(root), ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.Type().IsRegular() {
					files = append(files, path)
					want, _ := os.ReadFile(filepath.Join(root, path))
					got, err := fs.ReadFile(fsys, path)
					if err != nil || !bytes.Equal(got, want) {
						t.Errorf("seed %d: %s: content differs (%v)", seed, path, err)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := fstest.TestFS(fsys, files...); err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
		}
	}
}
