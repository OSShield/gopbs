package scan_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/osshield/gopbs/scan"
)

func TestParsePattern(t *testing.T) {
	for _, tc := range []struct {
		in                         string
		text                       string
		anchored, dirOnly, include bool
	}{
		{"*.tmp", "*.tmp", false, false, false},
		{"!keep.tmp", "keep.tmp", false, false, true},
		{"/etc/x", "etc/x", true, false, false},
		{"cache/", "cache", false, true, false},
		{"!/a/b/", "a/b", true, true, true},
		{"lit", "lit", false, false, false},
		{`\!bang`, `\!bang`, false, false, false},
	} {
		p, err := scan.ParsePattern(tc.in)
		if err != nil {
			t.Errorf("ParsePattern(%q): %v", tc.in, err)
			continue
		}
		if p.Text != tc.text || p.Anchored != tc.anchored || p.DirOnly != tc.dirOnly || p.Include != tc.include {
			t.Errorf("ParsePattern(%q) = %+v", tc.in, p)
		}
		if s := p.String(); s != tc.in {
			t.Errorf("ParsePattern(%q).String() = %q", tc.in, s)
		}
	}
}

func TestParsePatternErrors(t *testing.T) {
	for _, bad := range []string{"", "!", "/", "!/", "//", "[abc", `tail\`, "a\x00b", "a\nb", "[^]abc"} {
		_, err := scan.ParsePattern(bad)
		var pe *scan.PatternError
		if !errors.As(err, &pe) {
			t.Errorf("ParsePattern(%q) = %v, want *PatternError", bad, err)
			continue
		}
		if pe.Pattern != bad || !strings.Contains(err.Error(), "invalid exclude pattern") {
			t.Errorf("ParsePattern(%q) error = %v", bad, err)
		}
	}
	if _, err := scan.ParsePatterns([]string{"ok", "[bad"}); err == nil {
		t.Error("ParsePatterns must report the bad pattern")
	}
	if l, err := scan.ParsePatterns(nil); err != nil || l != nil {
		t.Errorf("ParsePatterns(nil) = %v, %v", l, err)
	}
}

// Matching rules, each verified against `pxar create --exclude` on the
// official client (see scan/glob.go).
func TestPatternMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		isDir, want   bool
	}{
		// basename at any depth
		{"*.tmp", "a.tmp", false, true},
		{"*.tmp", "a/b/c.tmp", false, true},
		{"*.tmp", "a.tmp/x", false, false},
		// suffix at component boundaries
		{"foo/bar", "foo/bar", false, true},
		{"foo/bar", "a/b/foo/bar", false, true},
		{"foo/bar", "a/xfoo/bar", false, false},
		{"foo/bar", "foo/bar/baz", false, false},
		{"c/d", "a/c/d", false, true},
		// anchored
		{"/foo/bar", "foo/bar", false, true},
		{"/foo/bar", "a/foo/bar", false, false},
		{"/c/d", "a/c/d", false, false},
		{"/anchored", "anchored", false, true},
		{"/anchored", "sub/anchored", false, false},
		// directories only
		{"cache/", "cache", true, true},
		{"cache/", "cache", false, false},
		{"cache/", "sub/cache", true, true},
		{"/cache/", "sub/cache", true, false},
		// ** as a whole component: zero or more, at least one when trailing
		{"**", "x", false, true},
		{"**", "a/b/c", false, true},
		{"**/x", "x", false, true},
		{"**/x", "a/b/x", false, true},
		{"**/x", "a/b/xy", false, false},
		{"a/**/b", "a/b", false, true},
		{"a/**/b", "a/c/d/b", false, true},
		{"a/**/b", "a/c/d/bb", false, false},
		{"a/**", "a", true, false},
		{"a/**", "a/b", false, true},
		{"a/**", "a/b/c", false, true},
		{"/a/**", "x/a/b", false, false},
		{"**/deep/*", "deep/f", false, true},
		{"**/deep/*", "sub/deep/x", false, true},
		{"**/deep/*", "q/deep.txt", false, false},
		// ** inside a component is a plain *
		{"a**b", "a/b", false, false},
		{"a**b", "axxb", false, true},
		{"s**l", "sxl", false, true},
		{"s**l", "s/x/l", false, false},
		{"x**", "xyz", false, true},
		// * and ? never cross / (unanchored, they still match any basename)
		{"*", "a/b", false, true},
		{"/*", "a/b", false, false},
		{"/*", "a", false, true},
		{"a/*", "a/b", false, true},
		{"a/*", "a/b/c", false, false},
		{"?", "a", false, true},
		{"?", "ab", false, false},
		{"?", "é", false, true},
		{"deep/*", "sub/deep/x", false, true},
		// a wildcard folder name matched by basename several levels down
		{"fol*_name", "path/to/folder_name", true, true},
		{"fol*_name", "a/path/to/folder_name", true, true},
		{"fol*_name", "folder_name", true, true},
		{"fol*_name/", "path/to/folder_name", true, true},
		{"fol*_name/", "path/to/folder_name", false, false},
		{"fol*_name", "path/to/folder_name.txt", false, false},
		{"fol*_name", "path/to/folder_name_x", true, false},
		{"fol*_name", "path/to/folder_name/inside", false, false},
		{"/fol*_name", "path/to/folder_name", true, false},
		{"to/fol*_name", "path/to/folder_name", true, true},
		{"path/*/fol*_name", "path/to/folder_name", true, true},
		{"path/fol*_name", "path/to/folder_name", true, false},
		// classes: [^…] negates, [!…] is a literal class
		{"[^a]", "a", false, false},
		{"[^a]", "x", false, true},
		{"[^a]", "ab", false, false},
		{"[!a]", "a", false, true},
		{"[!a]", "!", false, true},
		{"[!a]", "x", false, false},
		{"[a-c]x", "bx", false, true},
		{"[a-c]x", "dx", false, false},
		{"[]a]", "]", false, true},
		{"[]a]", "a", false, true},
		{"[a-]", "-", false, true},
		{`[\]]`, "]", false, true},
		{"[/]", "/", false, false},
		{"a[/]b", "a/b", false, false},
		{"a[/]b", "a", false, false},
		{`a\/b`, "a/b", false, false},
		{"[a/]", "a", false, true},
		{"x/[a/]", "x/a", false, true},
		// escapes
		{`\*lit`, "*lit", false, true},
		{`\*lit`, "xlit", false, false},
		{`\x`, "x", false, true},
		{`\x`, "sub/x", false, true},
		// literals
		{"lit", "lit", false, true},
		{"lit", "a/lit", false, true},
		{"lit", "alit", false, false},
		{"lit", "lit/x", false, false},
		// the root is never matched
		{"**", "", true, false},
		{"*", "", true, false},
	} {
		p, err := scan.ParsePattern(tc.pattern)
		if err != nil {
			t.Fatalf("ParsePattern(%q): %v", tc.pattern, err)
		}
		if got := p.Match(tc.path, tc.isDir); got != tc.want {
			t.Errorf("%q.Match(%q, dir=%v) = %v, want %v", tc.pattern, tc.path, tc.isDir, got, tc.want)
		}
	}
}

func TestPatternListLastWins(t *testing.T) {
	l, err := scan.ParsePatterns([]string{"*.tmp", "!keep.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(l scan.PatternList, path string, wantType scan.MatchType, wantOK bool) {
		t.Helper()
		mt, ok := l.Match(path, false)
		if ok != wantOK || (ok && mt != wantType) {
			t.Errorf("%v.Match(%q) = %v, %v; want %v, %v", l, path, mt, ok, wantType, wantOK)
		}
	}
	check(l, "keep.tmp", scan.MatchInclude, true)
	check(l, "sub/keep.tmp", scan.MatchInclude, true)
	check(l, "other.tmp", scan.MatchExclude, true)
	check(l, "x.log", 0, false)

	reversed := scan.PatternList{l[1], l[0]}
	check(reversed, "keep.tmp", scan.MatchExclude, true)
	check(scan.PatternList(nil), "anything", 0, false)
}

func TestPatternListString(t *testing.T) {
	l, err := scan.ParsePatterns([]string{"*.tmp", "!keep.tmp", "/abs", "cache/", "!/a/b/"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := l.String(), "*.tmp\n!keep.tmp\n/abs\ncache/\n!/a/b/\n"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if scan.PatternList(nil).String() != "" {
		t.Error("empty list must render empty")
	}
}

func TestGlobCompile(t *testing.T) {
	for _, ok := range []string{"a", "*", "**", "a/**/b", "[abc]", "[^abc]", "[]]", "[^]]", `\[`, `[\]]`, "[a-z]"} {
		if _, err := scan.CompileGlob(ok); err != nil {
			t.Errorf("CompileGlob(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"[", "[abc", "[]", "[^", `\`, `abc\`, `[\`} {
		if _, err := scan.CompileGlob(bad); err == nil {
			t.Errorf("CompileGlob(%q) accepted", bad)
		}
	}
}
