//go:build linux

package pxar_test

import (
	"bytes"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/scan"
	"golang.org/x/sys/unix"
)

// upstreamArchives writes a small tree with every common entry type and
// encodes it with the upstream pxar binary as a.pxar, a.mpxar and a.ppxar.
// It returns the tree and a reader for the archive files.
func upstreamArchives(t *testing.T) (src string, read func(name string) []byte, xattrs bool) {
	t.Helper()
	bin, err := exec.LookPath("pxar")
	if err != nil {
		t.Skip("pxar binary not installed")
	}
	src = t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(src, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	big := make([]byte, 3<<20)
	rand.New(rand.NewSource(1)).Read(big)
	for _, d := range []string{"dir", "dir/nested", "empty"} {
		if err := os.Mkdir(filepath.Join(src, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	write("big.bin", big, 0o600)
	write("dir/a.txt", []byte("alpha"), 0o751)
	write("dir/nested/b.txt", nil, 0o644)
	if err := os.Link(filepath.Join(src, "dir/a.txt"), filepath.Join(src, "z.hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir/a.txt", filepath.Join(src, "s.link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(src, "fifo"), 0o640); err != nil {
		t.Fatal(err)
	}
	xattrs = unix.Lsetxattr(filepath.Join(src, "dir/a.txt"), "user.note", []byte("x\x00y"), 0) == nil
	when := time.Unix(1_600_000_000, 123_456_789)
	if err := os.Chtimes(filepath.Join(src, "dir/a.txt"), when, when); err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if b, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Fatalf("pxar %v: %v\n%s", args, err, b)
		}
	}
	run("create", filepath.Join(out, "a.pxar"), src)
	run("create", "--payload-output", filepath.Join(out, "a.ppxar"), filepath.Join(out, "a.mpxar"), src)
	read = func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return src, read, xattrs
}

// Archives written by the upstream pxar encoder decode to exactly what is
// on disk, in v1 and split v2 form.
func TestReaderDecodesUpstreamArchives(t *testing.T) {
	src, read, xattrs := upstreamArchives(t)

	for name, r := range map[string]*pxar.Reader{
		"v1": pxar.NewReaderV1(bytes.NewReader(read("a.pxar"))),
		"v2": pxar.NewReaderV2(bytes.NewReader(read("a.mpxar")), bytes.NewReader(read("a.ppxar"))),
	} {
		t.Run(name, func(t *testing.T) {
			fsr, err := scan.DefaultReader()
			if err != nil {
				t.Fatal(err)
			}
			var paths []string
			for {
				n, err := r.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				paths = append(paths, n.Path)
				path := filepath.Join(src, n.Path)
				content, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("%q: %v", n.Path, err)
				}
				if n.Hardlink {
					if n.Path != "z.hardlink" || n.LinkTarget != "dir/a.txt" {
						t.Fatalf("hardlink %q -> %q", n.Path, n.LinkTarget)
					}
					continue
				}
				st, err := fsr.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				want := pxar.Entry{Mode: st.Mode, UID: st.UID, GID: st.GID, MtimeSecs: st.MtimeSecs, MtimeNanos: st.MtimeNanos}
				if n.Entry != want {
					t.Fatalf("%q: entry %+v, want %+v", n.Path, n.Entry, want)
				}
				switch {
				case st.Mode&scan.ModeTypeMask == scan.ModeRegular:
					disk, _ := os.ReadFile(path)
					if !bytes.Equal(content, disk) || n.Size != uint64(len(disk)) {
						t.Fatalf("%q: content differs", n.Path)
					}
				case st.Mode&scan.ModeTypeMask == scan.ModeSymlink:
					if target, _ := os.Readlink(path); n.LinkTarget != target {
						t.Fatalf("%q: symlink %q, want %q", n.Path, n.LinkTarget, target)
					}
				}
				if diskX, _ := fsr.Xattrs(path); !slices.EqualFunc(n.Xattrs, diskX, func(a, b pxar.Xattr) bool {
					return a.Name == b.Name && bytes.Equal(a.Value, b.Value)
				}) {
					t.Fatalf("%q: xattrs %v, want %v", n.Path, n.Xattrs, diskX)
				}
			}
			want := []string{"", "big.bin", "dir", "dir/a.txt", "dir/nested", "dir/nested/b.txt", "empty", "fifo", "s.link", "z.hardlink"}
			if !slices.Equal(paths, want) {
				t.Fatalf("paths %q, want %q", paths, want)
			}
		})
	}
	if !xattrs {
		t.Log("filesystem refused user xattrs; xattr decoding not exercised")
	}
}

// An upstream archive opened as a file system matches the tree on disk.
func TestFSUpstreamArchives(t *testing.T) {
	src, read, _ := upstreamArchives(t)
	v1, meta, payload := read("a.pxar"), read("a.mpxar"), read("a.ppxar")
	v1fs, err := pxar.OpenV1(bytes.NewReader(v1), int64(len(v1)))
	if err != nil {
		t.Fatal(err)
	}
	v2fs, err := pxar.OpenV2(bytes.NewReader(meta), int64(len(meta)), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for name, fsys := range map[string]*pxar.FS{"v1": v1fs, "v2": v2fs} {
		t.Run(name, func(t *testing.T) {
			if err := fstest.TestFS(fsys, "big.bin", "dir/a.txt", "dir/nested/b.txt", "empty", "z.hardlink"); err != nil {
				t.Fatal(err)
			}
			disk := os.DirFS(src)
			var walked int
			err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				walked++
				got, err := fsys.Lstat(path)
				if err != nil {
					return err
				}
				want, err := fs.Lstat(disk, path)
				if err != nil {
					return err
				}
				if got.Mode() != want.Mode() || !got.ModTime().Equal(want.ModTime()) ||
					(got.Mode().IsRegular() && got.Size() != want.Size()) {
					t.Errorf("%s: %v %v %d, want %v %v %d", path, got.Mode(), got.ModTime(), got.Size(),
						want.Mode(), want.ModTime(), want.Size())
				}
				if got.Mode().IsRegular() {
					a, err := fs.ReadFile(fsys, path)
					if err != nil {
						return err
					}
					if b, _ := fs.ReadFile(disk, path); !bytes.Equal(a, b) {
						t.Errorf("%s: content differs", path)
					}
				}
				return nil
			})
			if err != nil || walked != 10 {
				t.Fatalf("walk: %d entries, %v", walked, err)
			}
			if target, err := fsys.ReadLink("s.link"); err != nil || target != "dir/a.txt" {
				t.Fatalf("readlink: %q %v", target, err)
			}
			if got, err := fs.ReadFile(fsys, "s.link"); err != nil || string(got) != "alpha" {
				t.Fatalf("read through symlink: %q %v", got, err)
			}
		})
	}
}
