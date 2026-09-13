//go:build windows

package scan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsReaderClassifies(t *testing.T) {
	r := windowsReader{}
	root := t.TempDir()
	file := filepath.Join(root, "b.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 9, 1, 12, 0, 0, 500, time.UTC)
	if err := os.Chtimes(file, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	ro := filepath.Join(root, "ro.txt")
	if err := os.WriteFile(ro, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, filepath.Join(root, "b-hard.txt")); err != nil {
		t.Fatal(err)
	}

	st, err := r.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode&ModeTypeMask != ModeRegular || st.Mode&0o777 != 0o644 || st.Size != 5 || st.Nlink != 2 || st.MtimeSecs != stamp.Unix() {
		t.Errorf("file stat %+v", st)
	}
	hard, _ := r.Lstat(filepath.Join(root, "b-hard.txt"))
	if hard.Dev != st.Dev || hard.Ino != st.Ino {
		t.Errorf("hardlink identity differs: %+v vs %+v", hard, st)
	}
	if rs, _ := r.Lstat(ro); rs.Mode&0o777 != 0o444 {
		t.Errorf("read-only mode %o", rs.Mode&0o777)
	}
	if ds, _ := r.Lstat(filepath.Join(root, "a")); ds.Mode&ModeTypeMask != ModeDir {
		t.Errorf("dir stat %+v", ds)
	}
	names, err := r.ReadDirNames(root)
	if err != nil || len(names) != 4 || names[0] != "a" || names[1] != "b-hard.txt" {
		t.Errorf("dir names %v %v", names, err)
	}
	if err := os.Symlink(`a\sub`, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink creation needs privileges: %v", err)
	}
	ls, err := r.Lstat(filepath.Join(root, "link"))
	if err != nil || ls.Mode&ModeTypeMask != ModeSymlink {
		t.Errorf("symlink stat %+v %v", ls, err)
	}
	if target, _ := r.Readlink(filepath.Join(root, "link")); target != "a/sub" {
		t.Errorf("readlink %q", target)
	}
}

func TestWinPath(t *testing.T) {
	cases := map[string]string{
		`C:\dir\file`:      `\\?\C:\dir\file`,
		`\\server\share\d`: `\\?\UNC\server\share\d`,
		`\\?\C:\already`:   `\\?\C:\already`,
		`\\.\GLOBALROOT\x`: `\\.\GLOBALROOT\x`,
	}
	for in, want := range cases {
		if got := winPath(in); got != want {
			t.Errorf("winPath(%q) = %q, want %q", in, got, want)
		}
	}
	if s, n := splitNanos(-1); s != -1 || n != 999999999 {
		t.Errorf("splitNanos(-1) = %d %d", s, n)
	}
}
