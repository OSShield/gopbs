//go:build linux

package scan_test

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/osshield/gopbs/scan"
)

// writeTree creates the given relative files (content "x"); entries ending
// in "/" become directories. Parent directories are created as needed.
func writeTree(t *testing.T, root string, entries ...string) {
	t.Helper()
	for _, e := range entries {
		p := filepath.Join(root, e)
		if strings.HasSuffix(e, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// paths flattens a scanned tree into sorted archive-relative paths.
func paths(n *scan.Node) []string {
	var out []string
	var walk func(n *scan.Node, prefix string)
	walk = func(n *scan.Node, prefix string) {
		for _, c := range n.Children {
			p := c.Name
			if prefix != "" {
				p = prefix + "/" + c.Name
			}
			out = append(out, p)
			walk(c, p)
		}
	}
	walk(n, "")
	sort.Strings(out)
	return out
}

func assertPaths(t *testing.T, n *scan.Node, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := paths(n); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scanned paths:\n got  %v\n want %v", got, want)
	}
}

func scanWith(t *testing.T, root string, opts scan.Options) *scan.Node {
	t.Helper()
	n, err := mustScanner(t, opts).ScanDirectory(root, "")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScanExcludeFile(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "a.tmp", "a.txt", "sub/b.tmp", "sub/b.txt")
	n := scanWith(t, root, scan.Options{Exclude: []string{"*.tmp"}})
	assertPaths(t, n, "a.txt", "sub", "sub/b.txt")
}

// countingReader records which directories the scanner lists.
type countingReader struct {
	scan.MetadataReader
	listed map[string]int
}

func (c *countingReader) ReadDirNames(path string) ([]string, error) {
	c.listed[path]++
	return c.MetadataReader.ReadDirNames(path)
}

// An excluded directory is never listed, and a deeper re-include cannot
// resurrect it (upstream behaviour: the subtree is simply not visited).
func TestScanExcludeDirNotDescended(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "cache/inner/keep", "cache/x", "sub/cache/y", "ok")
	inner, err := scan.DefaultReader()
	if err != nil {
		t.Fatal(err)
	}
	r := &countingReader{inner, map[string]int{}}
	n := scanWith(t, root, scan.Options{
		Reader:  r,
		Exclude: []string{"cache/", "!cache/inner", "!cache/inner/keep"},
	})
	assertPaths(t, n, "ok", "sub")
	for dir := range r.listed {
		if strings.Contains(dir, "cache") {
			t.Errorf("excluded directory %s was listed", dir)
		}
	}
	if r.listed[root] != 1 || r.listed[filepath.Join(root, "sub")] != 1 {
		t.Errorf("listing counts: %v", r.listed)
	}
}

// A wildcard folder name excludes directories of that name wherever they
// sit in the tree (two and three levels down here), without touching files
// or differently named siblings — and the excluded directories are never
// listed.
func TestScanExcludeDirByWildcardDeep(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root,
		"path/to/folder_name/inside", "path/to/folder_name/deep/x",
		"top/folder_name/y", "folder_name/z",
		"path/to/folder_name.txt", "path/to/folder_name_x/keep", "path/to/other",
		"top/folder_name_file",
	)
	inner, err := scan.DefaultReader()
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"fol*_name", "fol*_name/"} {
		r := &countingReader{inner, map[string]int{}}
		n := scanWith(t, root, scan.Options{Reader: r, Exclude: []string{pattern}})
		assertPaths(t, n,
			"path", "path/to", "path/to/folder_name.txt", "path/to/folder_name_x", "path/to/folder_name_x/keep", "path/to/other",
			"top", "top/folder_name_file",
		)
		for dir := range r.listed {
			if filepath.Base(dir) == "folder_name" {
				t.Errorf("%s: excluded directory %s was listed", pattern, dir)
			}
		}
	}
	// Anchored at a deeper prefix: only that instance goes.
	n := scanWith(t, root, scan.Options{Exclude: []string{"/path/*/fol*_name/"}})
	assertPaths(t, n,
		"folder_name", "folder_name/z",
		"path", "path/to", "path/to/folder_name.txt", "path/to/folder_name_x", "path/to/folder_name_x/keep", "path/to/other",
		"top", "top/folder_name", "top/folder_name/y", "top/folder_name_file",
	)
}

func TestScanExcludeReinclude(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "a.tmp", "keep.tmp", "sub/keep.tmp", "sub/other.tmp")
	n := scanWith(t, root, scan.Options{Exclude: []string{"*.tmp", "!keep.tmp"}})
	assertPaths(t, n, "keep.tmp", "sub", "sub/keep.tmp")
}

func TestScanExcludeDirOnlyIgnoresFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "x/inside", "sub/x", "y")
	n := scanWith(t, root, scan.Options{Exclude: []string{"x/"}})
	assertPaths(t, n, "sub", "sub/x", "y")
}

func TestScanPxarExcludeDefaultOff(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "a.tmp")
	if err := os.WriteFile(filepath.Join(root, ".pxarexclude"), []byte("*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n := scanWith(t, root, scan.Options{})
	assertPaths(t, n, ".pxarexclude", "a.tmp")
}

// .pxarexclude patterns apply to their directory's subtree only: anchored
// lines relative to that directory, unanchored lines at any depth below it,
// all popped when the directory is left. CLI patterns stay active
// throughout, and the .pxarexclude file itself is archived.
func TestScanPxarExcludeScopingAndAnchoring(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root,
		"local", "globY", "anchored", "deep/local",
		"sub/local", "sub/deep/local", "sub/globX", "sub/glob-keep", "sub/anchored", "sub/nested/anchored",
		"other/local", "other/globZ", "other/a.tmp",
	)
	if err := os.WriteFile(filepath.Join(root, "sub", ".pxarexclude"),
		[]byte("  /local  \nglob*\n# comment\n\n!/glob-keep\r\n/nested/anchored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".pxarexclude"), []byte("/anchored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var excluded []string
	n := scanWith(t, root, scan.Options{
		Exclude:          []string{"*.tmp"},
		PxarExcludeFiles: true,
		OnExclude: func(path, archivePath string) {
			if !strings.HasPrefix(path, root) {
				t.Errorf("OnExclude path %q outside root", path)
			}
			excluded = append(excluded, archivePath)
		},
	})
	assertPaths(t, n,
		".pxarexclude", "local", "globY", "deep", "deep/local",
		"sub", "sub/.pxarexclude", "sub/deep", "sub/deep/local", "sub/glob-keep", "sub/anchored", "sub/nested",
		"other", "other/local", "other/globZ",
	)
	sort.Strings(excluded)
	if want := "anchored,other/a.tmp,sub/globX,sub/local,sub/nested/anchored"; strings.Join(excluded, ",") != want {
		t.Errorf("OnExclude got %v, want %s", excluded, want)
	}
}

func TestScanPxarExcludeBadLineWarns(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "a.tmp", "b.txt")
	if err := os.WriteFile(filepath.Join(root, ".pxarexclude"), []byte("[bad\n*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var warns []scan.Warning
	n := scanWith(t, root, scan.Options{
		PxarExcludeFiles: true,
		OnWarn:           func(w scan.Warning) { warns = append(warns, w) },
	})
	assertPaths(t, n, ".pxarexclude", "b.txt")
	if len(warns) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warns)
	}
	var pe *scan.PatternError
	if !errors.As(warns[0].Err, &pe) || pe.Pattern != "[bad" || !strings.HasSuffix(warns[0].Path, ".pxarexclude") {
		t.Errorf("warning = %+v", warns[0])
	}
}

func TestScanPxarExcludeReadErrorPolicy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission fixtures are ineffective")
	}
	root := t.TempDir()
	writeTree(t, root, "a.tmp")
	excl := filepath.Join(root, ".pxarexclude")
	if err := os.WriteFile(excl, []byte("*.tmp\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	// SkipQuotaProjIDs: the unreadable file would otherwise also fail its
	// own quota lookup (open for ioctl), which is not what is under test.
	if _, err := mustScanner(t, scan.Options{PxarExcludeFiles: true, SkipQuotaProjIDs: true}).ScanDirectory(root, ""); err == nil {
		t.Error("unreadable .pxarexclude must fail the scan by default")
	}
	var warns []scan.Warning
	n := scanWith(t, root, scan.Options{
		PxarExcludeFiles: true,
		SkipQuotaProjIDs: true,
		SkipOnError:      true,
		OnWarn:           func(w scan.Warning) { warns = append(warns, w) },
	})
	// The patterns could not be read, so nothing is excluded.
	assertPaths(t, n, ".pxarexclude", "a.tmp")
	if len(warns) != 1 || warns[0].Path != excl {
		t.Errorf("warnings = %+v", warns)
	}
}

// A .pxarexclude that is not a regular file is ignored (reading a fifo would
// block forever).
func TestScanPxarExcludeNonRegularIgnored(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "a.tmp")
	if err := os.Symlink("/nonexistent", filepath.Join(root, ".pxarexclude")); err != nil {
		t.Fatal(err)
	}
	n := scanWith(t, root, scan.Options{PxarExcludeFiles: true})
	assertPaths(t, n, ".pxarexclude", "a.tmp")
}

func TestScanFilterCallback(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "big", "small", "keep.tmp", "skip/inner", "sub/small")
	if err := os.WriteFile(filepath.Join(root, "big"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	n := scanWith(t, root, scan.Options{
		Exclude: []string{"*.tmp", "!keep.tmp"},
		Filter: func(path, archivePath string, st scan.Stat) bool {
			seen = append(seen, archivePath)
			if !strings.HasPrefix(path, root) {
				t.Errorf("Filter path %q outside root", path)
			}
			switch {
			case st.Mode&scan.ModeTypeMask == scan.ModeRegular && st.Size > 10:
				return false
			case archivePath == "skip":
				return false
			case archivePath == "keep.tmp":
				return false // vetoes the pattern re-include
			}
			return true
		},
	})
	assertPaths(t, n, "small", "sub", "sub/small")
	sort.Strings(seen)
	if want := "big,keep.tmp,skip,small,sub,sub/small"; strings.Join(seen, ",") != want {
		t.Errorf("Filter saw %v, want %s", seen, want)
	}
}

// When the first occurrence of a hardlinked inode is excluded, the next
// occurrence is archived as the regular file, not as a dangling hardlink.
func TestScanExcludeHardlinkFirstOccurrence(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "a.orig")
	for _, name := range []string{"b.copy", "c.copy"} {
		if err := os.Link(filepath.Join(root, "a.orig"), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	n := scanWith(t, root, scan.Options{Exclude: []string{"a.orig"}})
	assertPaths(t, n, "b.copy", "c.copy")
	if b := findChild(t, n, "b.copy"); b.Kind != scan.KindFile {
		t.Errorf("b.copy kind = %v, want file", b.Kind)
	}
	if c := findChild(t, n, "c.copy"); c.Kind != scan.KindHardlink || c.LinkTarget != "b.copy" {
		t.Errorf("c.copy kind=%v target=%q, want hardlink to b.copy", c.Kind, c.LinkTarget)
	}
}

func TestScanRootNeverExcluded(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "a", "b/c")
	s := mustScanner(t, scan.Options{Exclude: []string{"**"}})
	n, err := s.ScanDirectory(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Children) != 0 || n.Kind != scan.KindDirectory {
		t.Errorf("root = %+v", n)
	}
	// Multi-root style: the root node is returned even though "d1" would
	// match; its children are still filtered against the prefixed paths.
	s = mustScanner(t, scan.Options{Exclude: []string{"/d1", "/d1/a"}})
	n, err = s.ScanDirectory(root, "d1")
	if err != nil {
		t.Fatal(err)
	}
	assertPaths(t, n, "b", "b/c")
	f, err := s.ScanFile(filepath.Join(root, "a"), "a")
	if err != nil || f.Kind != scan.KindFile {
		t.Errorf("ScanFile of a matching root = %+v, %v", f, err)
	}
}

func TestNewScannerRejectsBadPattern(t *testing.T) {
	_, err := scan.NewScanner(scan.Options{Exclude: []string{"ok", "[bad"}})
	var pe *scan.PatternError
	if !errors.As(err, &pe) || pe.Pattern != "[bad" {
		t.Errorf("NewScanner error = %v", err)
	}
}
