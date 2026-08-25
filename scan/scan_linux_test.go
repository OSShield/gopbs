//go:build linux

package scan_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osshield/gopbs/scan"
	"golang.org/x/sys/unix"
)

func mustScanner(t *testing.T, opts scan.Options) *scan.Scanner {
	t.Helper()
	s, err := scan.NewScanner(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func findChild(t *testing.T, n *scan.Node, name string) *scan.Node {
	t.Helper()
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("child %q not found in %q (have %d children)", name, n.Name, len(n.Children))
	return nil
}

// Builds a fixture tree exercising every scannable kind available to an
// unprivileged test and verifies the resulting node tree.
func TestScanDirectory(t *testing.T) {
	root := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "sub", "inner"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("hello scan"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "data.bin"), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../b.txt", filepath.Join(root, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "b.txt"), filepath.Join(root, "sub", "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "a.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := mustScanner(t, scan.Options{}).ScanDirectory(root, "")
	if err != nil {
		t.Fatal(err)
	}

	if n.Kind != scan.KindDirectory {
		t.Fatalf("root kind = %v", n.Kind)
	}
	// Children sorted by name byte order: a.fifo, b.txt, sub.
	gotNames := make([]string, len(n.Children))
	for i, c := range n.Children {
		gotNames[i] = c.Name
	}
	if strings.Join(gotNames, ",") != "a.fifo,b.txt,sub" {
		t.Errorf("root children = %v", gotNames)
	}

	fifo := findChild(t, n, "a.fifo")
	if fifo.Kind != scan.KindFifo {
		t.Errorf("a.fifo kind = %v", fifo.Kind)
	}

	file := findChild(t, n, "b.txt")
	if file.Kind != scan.KindFile || file.Stat.Size != 10 {
		t.Errorf("b.txt kind=%v size=%d", file.Kind, file.Stat.Size)
	}
	if file.Stat.Mode&0o7777 != 0o640 {
		t.Errorf("b.txt mode = %o", file.Stat.Mode&0o7777)
	}
	info, err := os.Lstat(filepath.Join(root, "b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if file.Stat.MtimeSecs != info.ModTime().Unix() {
		t.Errorf("b.txt mtime = %d, want %d", file.Stat.MtimeSecs, info.ModTime().Unix())
	}
	if file.Stat.UID != uint32(os.Getuid()) || file.Stat.GID != uint32(os.Getgid()) {
		t.Errorf("b.txt uid/gid = %d/%d", file.Stat.UID, file.Stat.GID)
	}

	sub := findChild(t, n, "sub")
	if sub.Stat.Mode&0o7777 != 0o750 {
		t.Errorf("sub mode = %o", sub.Stat.Mode&0o7777)
	}

	link := findChild(t, sub, "link")
	if link.Kind != scan.KindSymlink || link.LinkTarget != "../b.txt" {
		t.Errorf("link kind=%v target=%q", link.Kind, link.LinkTarget)
	}

	// b.txt was scanned first (byte order), so sub/hardlink is the second
	// occurrence and must reference it by archive path.
	hl := findChild(t, sub, "hardlink")
	if hl.Kind != scan.KindHardlink || hl.LinkTarget != "b.txt" {
		t.Errorf("hardlink kind=%v target=%q", hl.Kind, hl.LinkTarget)
	}
}

// Hardlink identity must survive across multiple roots scanned by the same
// Scanner (multi-add archives).
func TestScanHardlinkAcrossRoots(t *testing.T) {
	base := t.TempDir()
	d1 := filepath.Join(base, "d1")
	d2 := filepath.Join(base, "d2")
	for _, d := range []string{d1, d2} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d1, "orig"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(d1, "orig"), filepath.Join(d2, "copy")); err != nil {
		t.Fatal(err)
	}

	s := mustScanner(t, scan.Options{})
	if _, err := s.ScanDirectory(d1, "d1"); err != nil {
		t.Fatal(err)
	}
	n2, err := s.ScanDirectory(d2, "d2")
	if err != nil {
		t.Fatal(err)
	}
	cp := findChild(t, n2, "copy")
	if cp.Kind != scan.KindHardlink || cp.LinkTarget != "d1/orig" {
		t.Errorf("cross-root hardlink kind=%v target=%q, want d1/orig", cp.Kind, cp.LinkTarget)
	}
}

func TestScanXattrs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lsetxattr(path, "user.gopbs_b", []byte("two"), 0); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
			t.Skip("filesystem does not support user xattrs")
		}
		t.Fatal(err)
	}
	if err := unix.Lsetxattr(path, "user.gopbs_a", []byte("one"), 0); err != nil {
		t.Fatal(err)
	}

	n, err := mustScanner(t, scan.Options{}).ScanDirectory(root, "")
	if err != nil {
		t.Fatal(err)
	}
	f := findChild(t, n, "f")
	if len(f.Xattrs) != 2 || f.Xattrs[0].Name != "user.gopbs_a" || f.Xattrs[1].Name != "user.gopbs_b" {
		t.Fatalf("xattrs = %+v, want gopbs_a then gopbs_b", f.Xattrs)
	}
	if string(f.Xattrs[0].Value) != "one" || string(f.Xattrs[1].Value) != "two" {
		t.Errorf("xattr values = %q %q", f.Xattrs[0].Value, f.Xattrs[1].Value)
	}
}

func TestScanSkipOnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission fixtures are ineffective")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	if err := os.WriteFile(filepath.Join(root, "ok"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default policy: fail.
	if _, err := mustScanner(t, scan.Options{}).ScanDirectory(root, ""); err == nil {
		t.Fatal("expected error scanning unreadable subdirectory")
	}

	// SkipOnError: warn and omit.
	var warns []scan.Warning
	s := mustScanner(t, scan.Options{
		SkipOnError: true,
		OnWarn:      func(w scan.Warning) { warns = append(warns, w) },
	})
	n, err := s.ScanDirectory(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Children) != 1 || n.Children[0].Name != "ok" {
		t.Errorf("children after skip = %+v", n.Children)
	}
	if len(warns) != 1 || !strings.Contains(warns[0].Path, "locked") {
		t.Errorf("warnings = %+v", warns)
	}
}

func TestScanFileRejectsDirectory(t *testing.T) {
	s := mustScanner(t, scan.Options{})
	if _, err := s.ScanFile(t.TempDir(), ""); err == nil {
		t.Error("ScanFile on a directory must fail")
	}
	if _, err := s.ScanDirectory(filepath.Join(t.TempDir(), "nope"), ""); err == nil {
		t.Error("ScanDirectory on a missing path must fail")
	}
}

func TestVirtualRootAndStreams(t *testing.T) {
	f1, err := scan.StreamNode("dump.sql", 128, strings.NewReader(strings.Repeat("x", 128)))
	if err != nil {
		t.Fatal(err)
	}
	if f1.Kind != scan.KindStream || f1.Stat.Size != 128 || f1.Stat.Mode&scan.ModeTypeMask != scan.ModeRegular {
		t.Errorf("stream node = %+v", f1)
	}
	if _, err := scan.StreamNode("bad/name", 1, strings.NewReader("x")); err == nil {
		t.Error("invalid stream name must fail")
	}
	if _, err := scan.StreamNode("neg", -1, strings.NewReader("x")); err == nil {
		t.Error("negative stream size must fail")
	}

	f2, err := scan.StreamNode("a.first", 0, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	root, err := scan.VirtualRoot("backup", []*scan.Node{f1, f2})
	if err != nil {
		t.Fatal(err)
	}
	if root.Kind != scan.KindDirectory || root.Stat.Mode != scan.ModeDir|0o777 {
		t.Errorf("virtual root = %+v", root)
	}
	if root.Children[0].Name != "a.first" || root.Children[1].Name != "dump.sql" {
		t.Errorf("virtual root children unsorted: %v, %v", root.Children[0].Name, root.Children[1].Name)
	}

	if _, err := scan.VirtualRoot("backup", []*scan.Node{f1, f1}); err == nil {
		t.Error("duplicate top-level names must fail")
	}
}
