package scan

import (
	"errors"
	"fmt"
	"strings"
)

// MatchType is the verdict of a pattern hit.
type MatchType int

const (
	// MatchExclude: the entry is left out of the archive.
	MatchExclude MatchType = iota
	// MatchInclude: the entry is kept even if an earlier pattern excluded it.
	MatchInclude
)

// Pattern is one exclude pattern in proxmox-backup-client syntax:
//
//   - a leading '!' turns the pattern into an include (re-include) pattern;
//   - a leading '/' anchors it: it must match the whole archive-relative
//     path. Unanchored patterns match at any depth (every suffix of the path
//     starting at a component boundary is tried, so "*.tmp" matches by
//     basename and "foo/bar" matches "a/b/foo/bar");
//   - a trailing '/' restricts the pattern to directories;
//   - the body is an fnmatch(3)-style glob with FNM_PATHNAME semantics:
//     '*', '?' and '[…]' classes never match '/' ('[^…]' negates a class),
//     '\' escapes the next character, and '**' as a whole component matches
//     zero or more components ("a/**/b" matches "a/b" and "a/x/y/b"), or at
//     least one at the end of a pattern ("a/**" matches a's contents, not a).
//
// Patterns without glob metacharacters are compared literally. The rules
// match the official client's, verified against `pxar create --exclude`.
type Pattern struct {
	Text     string // body: no leading '!' or '/', no trailing '/'
	Anchored bool   // leading '/'
	DirOnly  bool   // trailing '/'
	Include  bool   // leading '!'

	g *glob // nil: Text is a literal
}

// PatternList is an ordered list of patterns evaluated last-match-wins.
type PatternList []Pattern

// PatternError reports an exclude pattern that failed to parse.
type PatternError struct {
	Pattern string
	Err     error
}

func (e *PatternError) Error() string {
	return fmt.Sprintf("scan: invalid exclude pattern %q: %v", e.Pattern, e.Err)
}

func (e *PatternError) Unwrap() error { return e.Err }

var errEmptyPattern = errors.New("empty pattern")

// ParsePattern parses one pattern; errors are *PatternError.
func ParsePattern(s string) (Pattern, error) {
	var p Pattern
	body := s
	if strings.HasPrefix(body, "!") {
		p.Include = true
		body = body[1:]
	}
	if strings.HasPrefix(body, "/") {
		p.Anchored = true
		body = body[1:]
	}
	if strings.HasSuffix(body, "/") {
		p.DirOnly = true
		body = body[:len(body)-1]
	}
	if body == "" {
		return Pattern{}, &PatternError{s, errEmptyPattern}
	}
	if strings.ContainsAny(body, "\x00\n") {
		return Pattern{}, &PatternError{s, errors.New("NUL or newline in pattern")}
	}
	p.Text = body
	if strings.ContainsAny(body, `*?[\`) {
		g, err := compileGlob(body)
		if err != nil {
			return Pattern{}, &PatternError{s, err}
		}
		p.g = g
	}
	return p, nil
}

// ParsePatterns parses each pattern in order, stopping at the first error.
func ParsePatterns(ss []string) (PatternList, error) {
	if len(ss) == 0 {
		return nil, nil
	}
	out := make(PatternList, 0, len(ss))
	for _, s := range ss {
		p, err := ParsePattern(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// String renders the pattern in its source form — the line format
// proxmox-backup-client records in .pxarexclude-cli and the v2 prelude.
func (p Pattern) String() string {
	var b strings.Builder
	b.Grow(len(p.Text) + 3)
	if p.Include {
		b.WriteByte('!')
	}
	if p.Anchored {
		b.WriteByte('/')
	}
	b.WriteString(p.Text)
	if p.DirOnly {
		b.WriteByte('/')
	}
	return b.String()
}

// Match reports whether the pattern applies to the entry at archivePath (a
// slash-separated path relative to the archive root, no leading slash). The
// archive root itself is never matched.
func (p Pattern) Match(archivePath string, isDir bool) bool {
	if p.DirOnly && !isDir {
		return false
	}
	if archivePath == "" {
		return false
	}
	if p.g == nil {
		if p.Anchored {
			return archivePath == p.Text
		}
		return archivePath == p.Text || strings.HasSuffix(archivePath, "/"+p.Text)
	}
	comps := strings.Split(archivePath, "/")
	if p.Anchored {
		return p.g.match(comps)
	}
	for i := range comps {
		if p.g.match(comps[i:]) {
			return true
		}
	}
	return false
}

// Match evaluates the list last-match-wins: the latest pattern that matches
// decides. ok is false when no pattern matches (the entry is included).
func (l PatternList) Match(archivePath string, isDir bool) (mt MatchType, ok bool) {
	for i := len(l) - 1; i >= 0; i-- {
		if l[i].Match(archivePath, isDir) {
			if l[i].Include {
				return MatchInclude, true
			}
			return MatchExclude, true
		}
	}
	return MatchExclude, false
}

// String renders the list one pattern per line, newline-terminated — the
// exact content of proxmox-backup-client's .pxarexclude-cli / v2 prelude.
func (l PatternList) String() string {
	var b strings.Builder
	for _, p := range l {
		b.WriteString(p.String())
		b.WriteByte('\n')
	}
	return b.String()
}
