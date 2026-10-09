//go:build linux

package scan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/osshield/gopbs/scan"
)

// A root that is a symlink to a directory is scanned as that directory (the
// way a shadow copy exposed through a link is), children opened via the link
func TestScanRootThroughSymlink(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	s, err := scan.NewScanner(scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.ScanDirectory(link, "")
	if err != nil {
		t.Fatalf("scan through link: %v", err)
	}
	if root.Kind != scan.KindDirectory || len(root.Children) != 1 || root.Children[0].Name != "f.txt" {
		t.Fatalf("root %+v children %d", root.Kind, len(root.Children))
	}
	if root.Children[0].Path != filepath.Join(link, "f.txt") {
		t.Errorf("child path %s should go through the link", root.Children[0].Path)
	}
}
