//go:build integration

package main_test

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/osshield/gopbs/catalog"
)

// The exclusion fixture. Patterns given on the command line to both
// archivers (see compose.yml):
//
//	*.tmp  !keep.tmp  cache/  /anchored  **/deep/*  fol*_name/
//
// plus two .pxarexclude files inside the tree. Anchored lines live only in
// the root .pxarexclude: the official client ignores anchored lines in
// subdirectory .pxarexclude files (it prefixes them with the directory path
// but then matches without the leading slash), while gopbs implements the
// documented behaviour — a deliberate divergence kept out of the fixture.
var (
	excludeFixtureFiles = []string{
		"a.tmp", "keep.tmp", "a.txt",
		"cache/x", "sub/cache/y", "cachefile",
		"anchored", "sub/anchored",
		"x/deep/y.bak", "deep/f", "q/deep.txt",
		"rootonly", "sub/rootonly", "globX", "sub/globY", "glob-keep", "sub/glob-keep",
		"sub/local", "sub/inner/local", "sub/other/z", "sub/otherfile", "other/z",
		"path/to/folder_name/inside", "path/to/folder_name/deep/x", "path/to/folder_name.txt", "top/folder_name/y",
		".pxarexclude-cli", // a real file of the reserved name: dropped by both
	}
	excludeFixturePxarexclude = map[string]string{
		".pxarexclude":     "/rootonly\nglob*\n!glob-keep\n# comment\n",
		"sub/.pxarexclude": "local\nother/\n",
	}
	// What must survive: everything the patterns leave, both .pxarexclude
	// files, and the synthetic .pxarexclude-cli.
	excludeFixtureRestored = []string{
		".pxarexclude", "keep.tmp", "a.txt", "cachefile", "sub", "sub/anchored", "sub/.pxarexclude",
		"x", "deep", "q", "q/deep.txt",
		"sub/rootonly", "glob-keep", "sub/glob-keep",
		"sub/inner", "sub/otherfile", "other", "other/z",
		"path", "path/to", "path/to/folder_name.txt", "top",
		"x/deep", // **/deep/* empties deep directories but keeps them
		".pxarexclude-cli",
	}
	excludeCLIContent = "*.tmp\n!keep.tmp\ncache/\n/anchored\n**/deep/*\nfol*_name/\n"
)

func makeExcludeTree() {
	for _, f := range excludeFixtureFiles {
		p := filepath.Join(sourceExclDir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			log.Fatalf("exclude fixture: %v", err)
		}
		if err := os.WriteFile(p, []byte("content of "+f+"\n"), 0o644); err != nil {
			log.Fatalf("exclude fixture: %v", err)
		}
	}
	for f, content := range excludeFixturePxarexclude {
		if err := os.WriteFile(filepath.Join(sourceExclDir, f), []byte(content), 0o644); err != nil {
			log.Fatalf("exclude fixture: %v", err)
		}
	}
}

// TestExcludeComparison requires the gopbs archives built with exclude
// patterns to restore to exactly the tree the official CLI's does, that tree
// to be the expected one, and the recorded .pxarexclude-cli to match.
func TestExcludeComparison(t *testing.T) {
	if _, err := os.Stat(filepath.Join(restoreDir, "pbs-excl")); err != nil {
		// TestComparison runs the restore container; run it here when this
		// test is selected on its own.
		if err := compose("run", "--rm", "--remove-orphans", "restore"); err != nil {
			t.Fatalf("restore: %v", err)
		}
	}
	official := filepath.Join(restoreDir, "pbs-excl")
	officialEntries, err := collectEntries(official)
	if err != nil {
		t.Fatal(err)
	}
	for _, ours := range []string{"gopbs-excl", "gopbs-excl-split"} {
		dir := filepath.Join(restoreDir, ours)
		want := officialEntries
		if ours == "gopbs-excl-split" {
			// The split archive records the patterns in its prelude, not
			// as a file, so its restored tree has no .pxarexclude-cli.
			want = make(map[string]treeEntry, len(officialEntries))
			for rel, e := range officialEntries {
				if rel != ".pxarexclude-cli" {
					want[rel] = e
				}
			}
		}
		got, err := collectEntries(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Errorf("%s has %d entries, %s %d", dir, len(got), official, len(want))
		}
		for rel, e := range want {
			if g, ok := got[rel]; !ok || g != e {
				t.Errorf("%s: %s missing or different from %s", dir, rel, official)
			}
		}
	}

	entries, err := collectEntries(filepath.Join(restoreDir, "gopbs-excl"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rel := range entries {
		got = append(got, rel)
	}
	sort.Strings(got)
	want := append([]string(nil), excludeFixtureRestored...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("restored tree:\n got  %v\n want %v", got, want)
	}

	for _, dir := range []string{"pbs-excl", "gopbs-excl"} {
		content, err := os.ReadFile(filepath.Join(restoreDir, dir, ".pxarexclude-cli"))
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != excludeCLIContent {
			t.Errorf("%s/.pxarexclude-cli = %q, want %q", dir, content, excludeCLIContent)
		}
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "gopbs-excl-split", ".pxarexclude-cli")); !os.IsNotExist(err) {
		t.Errorf("split archive must not carry .pxarexclude-cli (stat: %v)", err)
	}
}

// TestExcludeBytes requires the exclude archives to be byte-identical to
// the official CLI's: v1 (including the synthetic .pxarexclude-cli entry and
// its position) and the split pair (including the JSON prelude).
func TestExcludeBytes(t *testing.T) {
	for _, name := range []string{"pxar", "mpxar", "ppxar"} {
		ours, err := os.ReadFile(filepath.Join(pxarDir, "gopbs-excl."+name))
		if err != nil {
			t.Fatal(err)
		}
		official, err := os.ReadFile(filepath.Join(pxarDir, "pbs-excl."+name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ours, official) {
			t.Errorf("%s differs from the official encoder's (%d vs %d bytes)", name, len(ours), len(official))
		}
	}
}

// TestExcludeCatalog checks the v1 catalog of the exclude archive: excluded
// entries absent, the synthetic .pxarexclude-cli listed with mtime 0.
func TestExcludeCatalog(t *testing.T) {
	root := decodeCatalog(t, filepath.Join(pxarDir, "gopbs-excl.pcat1"))
	top := root.Child("backup.pxar.didx")
	if top == nil {
		t.Fatalf("archive entry missing (children: %v)", childNames(root))
	}
	cli := top.Child(".pxarexclude-cli")
	if cli == nil || cli.Type != catalog.TypeFile || cli.Size != uint64(len(excludeCLIContent)) || cli.MtimeSecs != 0 {
		t.Errorf(".pxarexclude-cli catalog entry = %+v", cli)
	}
	for _, absent := range []string{"a.tmp", "cache", "anchored", "rootonly", "globX"} {
		if top.Child(absent) != nil {
			t.Errorf("%s present in catalog", absent)
		}
	}
	if to := top.Child("path").Child("to"); to == nil || to.Child("folder_name") != nil || to.Child("folder_name.txt") == nil {
		t.Errorf("path/to in catalog = %+v", to)
	}
	if diff := compareCatalogWithSource(top, filepath.Join(restoreDir, "gopbs-excl")); diff != "" {
		t.Errorf("catalog vs restored tree: %s", diff)
	}
}
