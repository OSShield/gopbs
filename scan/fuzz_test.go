package scan_test

import (
	"strings"
	"testing"

	"github.com/osshield/gopbs/scan"
)

// FuzzParsePattern throws arbitrary patterns and paths at the parser and
// matcher: neither may panic, and an accepted pattern must survive a
// String() round trip with identical matching behaviour.
func FuzzParsePattern(f *testing.F) {
	for _, p := range []string{"*.tmp", "!keep.tmp", "/a/**/b", "cache/", "[^a-c]x", `\*`, "**", "[]]", "[!a]"} {
		f.Add(p, "a/b/c.tmp", false)
		f.Add(p, "cache", true)
	}
	f.Fuzz(func(t *testing.T, pattern, path string, isDir bool) {
		p, err := scan.ParsePattern(pattern)
		if err != nil {
			return
		}
		again, err := scan.ParsePattern(p.String())
		if err != nil {
			t.Fatalf("round trip of %q (%q) failed: %v", pattern, p.String(), err)
		}
		if again.Text != p.Text || again.Anchored != p.Anchored || again.DirOnly != p.DirOnly || again.Include != p.Include {
			t.Fatalf("round trip of %q changed the pattern: %+v vs %+v", pattern, p, again)
		}
		path = strings.TrimPrefix(path, "/")
		if p.Match(path, isDir) != again.Match(path, isDir) {
			t.Fatalf("round trip of %q changed matching of %q", pattern, path)
		}
	})
}

// FuzzGlob exercises the component matcher directly: compile must reject
// or accept without panicking, and accepted globs must match anything.
func FuzzGlob(f *testing.F) {
	f.Add("a/**/b", "a/x/b")
	f.Add("[^a]*", "b/c")
	f.Add(`\`, "x")
	f.Add("[", "x")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		g, err := scan.CompileGlob(pattern)
		if err != nil {
			return
		}
		g.Match(strings.Split(path, "/"))
	})
}
