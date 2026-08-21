//go:build integration

package main_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/scheiblingco/gopbs/catalog"
)

// TestCatalogComparison validates the gopbs .pcat1 catalog two ways: it must
// describe the source tree exactly, and it must be semantically identical to
// the catalog written by tizbac's implementation (the reference proven
// against live PBS). Byte equality is not expected: tizbac groups directory
// entries before file entries within a table, while gopbs follows upstream
// proxmox-backup's interleaved walk order; both decode identically.
func TestCatalogComparison(t *testing.T) {
	gop := decodeCatalog(t, filepath.Join(pxarDir, "gopbs.pcat1"))
	tiz := decodeCatalog(t, filepath.Join(pxarDir, "tizbac.pcat1"))

	if diff := compareCatalogDirs(gop, tiz, "/"); diff != "" {
		t.Errorf("gopbs vs tizbac catalog: %s", diff)
	}

	gopTop := gop.Child("backup.pxar.didx")
	if gopTop == nil {
		t.Fatalf("gopbs catalog: archive entry missing (children: %v)", childNames(gop))
	}
	if diff := compareCatalogWithSource(gopTop, sourceDir); diff != "" {
		t.Errorf("gopbs catalog vs source tree: %s", diff)
	}
}

func decodeCatalog(t *testing.T, path string) *catalog.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := catalog.Decode(data)
	if err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return root
}

func childNames(e *catalog.Entry) []string {
	names := make([]string, len(e.Children))
	for i, c := range e.Children {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}

// compareCatalogDirs compares two decoded catalog directories recursively,
// ignoring entry order within tables. Returns "" when equal, else a
// description of the first difference.
func compareCatalogDirs(a, b *catalog.Entry, path string) string {
	an, bn := childNames(a), childNames(b)
	if fmt.Sprint(an) != fmt.Sprint(bn) {
		return fmt.Sprintf("%s: children %v vs %v", path, an, bn)
	}
	for _, name := range an {
		ca, cb := a.Child(name), b.Child(name)
		p := path + name
		if ca.Type != cb.Type {
			return fmt.Sprintf("%s: type %c vs %c", p, ca.Type, cb.Type)
		}
		switch ca.Type {
		case catalog.TypeFile:
			if ca.Size != cb.Size || ca.MtimeSecs != cb.MtimeSecs {
				return fmt.Sprintf("%s: file (%d,%d) vs (%d,%d)", p, ca.Size, ca.MtimeSecs, cb.Size, cb.MtimeSecs)
			}
		case catalog.TypeDirectory:
			if diff := compareCatalogDirs(ca, cb, p+"/"); diff != "" {
				return diff
			}
		}
	}
	return ""
}

// compareCatalogWithSource walks the source tree and requires the catalog
// directory to mirror it: same names, kinds, file sizes and mtimes.
func compareCatalogWithSource(dir *catalog.Entry, root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err.Error()
	}
	var names []string
	for _, e := range entries {
		if e.Name() == ".gitkeep" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if fmt.Sprint(names) != fmt.Sprint(childNames(dir)) {
		return fmt.Sprintf("%s: entries %v vs catalog %v", root, names, childNames(dir))
	}

	for _, name := range names {
		c := dir.Child(name)
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err.Error()
		}
		switch {
		case info.IsDir():
			if c.Type != catalog.TypeDirectory {
				return fmt.Sprintf("%s: dir on disk, %c in catalog", path, c.Type)
			}
			if diff := compareCatalogWithSource(c, path); diff != "" {
				return diff
			}
		case info.Mode().IsRegular():
			if c.Type != catalog.TypeFile {
				return fmt.Sprintf("%s: file on disk, %c in catalog", path, c.Type)
			}
			if c.Size != uint64(info.Size()) || c.MtimeSecs != info.ModTime().Unix() {
				return fmt.Sprintf("%s: (%d,%d) on disk, (%d,%d) in catalog",
					path, info.Size(), info.ModTime().Unix(), c.Size, c.MtimeSecs)
			}
		}
	}
	return ""
}
