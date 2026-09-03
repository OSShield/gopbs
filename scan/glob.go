package scan

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// glob is a compiled exclude-pattern body: the pattern split into path
// components, matched with fnmatch(3) FNM_PATHNAME semantics ('*', '?' and
// bracket classes never cross '/') plus the '**' component, which matches
// zero or more whole components — except at the end of a pattern, where it
// needs at least one ("a/**" matches a's contents, not a). Both details,
// and '[^…]' (not '[!…]') as the negated class, mirror the official
// client's pathpatterns engine, verified against `pxar create --exclude`.
type glob struct {
	comps []string
}

var (
	errUnterminatedClass = errors.New("unterminated character class")
	errTrailingEscape    = errors.New("trailing backslash")
)

// compileGlob validates pat and splits it into components. It rejects an
// unterminated '[' class and a trailing '\', the only syntax errors fnmatch
// has; everything else is a valid (if possibly unmatchable) pattern. A '/'
// inside a class or after a backslash does not split (and, as with
// FNM_PATHNAME, can never match anything: components hold no slashes).
func compileGlob(pat string) (*glob, error) {
	var comps []string
	start := 0
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '/':
			comps = append(comps, pat[start:i])
			start = i + 1
		case '\\':
			if i+1 >= len(pat) {
				return nil, errTrailingEscape
			}
			i++
		case '[':
			j := i + 1
			if j < len(pat) && pat[j] == '^' {
				j++
			}
			if j < len(pat) && pat[j] == ']' { // leading ']' is literal
				j++
			}
			for ; j < len(pat) && pat[j] != ']'; j++ {
				if pat[j] == '\\' {
					j++
				}
			}
			if j >= len(pat) {
				return nil, errUnterminatedClass
			}
			i = j
		}
	}
	comps = append(comps, pat[start:])
	return &glob{comps: comps}, nil
}

// match reports whether the whole component list matches the pattern.
func (g *glob) match(comps []string) bool {
	return matchComps(g.comps, comps)
}

func matchComps(pat, path []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for len(pat) > 0 && pat[0] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 0 {
				return len(path) > 0 // trailing "**": at least one component
			}
			for i := 0; i <= len(path); i++ {
				if matchComps(pat, path[i:]) {
					return true
				}
			}
			return false
		}
		if len(path) == 0 {
			return false
		}
		if !matchComponent(pat[0], path[0]) {
			return false
		}
		pat, path = pat[1:], path[1:]
	}
	return len(path) == 0
}

// matchComponent matches one pattern component against one path component
// (neither contains '/'). The pattern has been validated by compileGlob.
func matchComponent(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for len(p) > 0 && p[0] == '*' {
				p = p[1:]
			}
			if len(p) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchComponent(p, s[i:]) {
					return true
				}
			}
			return false

		case '?':
			if len(s) == 0 {
				return false
			}
			_, n := utf8.DecodeRuneInString(s)
			p, s = p[1:], s[n:]

		case '[':
			if len(s) == 0 {
				return false
			}
			r, n := utf8.DecodeRuneInString(s)
			rest, ok := matchClass(p[1:], r)
			if !ok {
				return false
			}
			p, s = rest, s[n:]

		case '\\':
			p = p[1:]
			fallthrough

		default:
			_, n := utf8.DecodeRuneInString(p)
			if !strings.HasPrefix(s, p[:n]) {
				return false
			}
			p, s = p[n:], s[n:]
		}
	}
	return len(s) == 0
}

// matchClass matches r against the bracket class whose body starts at p
// (just past the '['). It returns the pattern remainder after the closing
// ']' and whether r matched.
func matchClass(p string, r rune) (rest string, ok bool) {
	negate := false
	if len(p) > 0 && p[0] == '^' {
		negate = true
		p = p[1:]
	}
	matched := false
	first := true
	for {
		if len(p) > 0 && p[0] == ']' && !first {
			break
		}
		first = false
		lo, n := classRune(p)
		p = p[n:]
		hi := lo
		if len(p) >= 2 && p[0] == '-' && p[1] != ']' {
			hi, n = classRune(p[1:])
			p = p[1+n:]
		}
		if lo <= r && r <= hi {
			matched = true
		}
	}
	return p[1:], matched != negate
}

// classRune decodes the next class member, honouring '\' escapes.
func classRune(p string) (rune, int) {
	if p[0] == '\\' && len(p) > 1 {
		r, n := utf8.DecodeRuneInString(p[1:])
		return r, n + 1
	}
	return utf8.DecodeRuneInString(p)
}
