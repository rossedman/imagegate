package policy

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// glob matches a normalized repository. "*" and "?" stop at "/", "**"
// crosses it. Tags and digests are not part of the match.
type glob struct {
	re *regexp.Regexp
}

// compileGlob turns an images pattern into an anchored regexp, rejecting
// patterns that carry a tag or digest.
func compileGlob(pattern string) (glob, error) {
	if pattern == "" {
		return glob{}, fmt.Errorf("empty image glob")
	}
	// YAML documents are UTF-8, so this only guards direct callers.
	if !utf8.ValidString(pattern) {
		return glob{}, fmt.Errorf("image glob %q is not valid UTF-8", pattern)
	}
	if strings.ContainsAny(pattern, "@") || strings.Contains(lastSegment(pattern), ":") {
		return glob{}, fmt.Errorf("image glob %q must not include a tag or digest; verification is by digest", pattern)
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		// Quote whole runes: string(pattern[i]) would re-encode each byte
		// of a multi-byte rune as its own rune.
		r, size := utf8.DecodeRuneInString(pattern[i:])
		switch {
		case r == '*' && strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			size = 2
		case r == '*':
			b.WriteString("[^/]*")
		case r == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+size]))
		}
		i += size
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return glob{}, fmt.Errorf("image glob %q: %w", pattern, err)
	}
	return glob{re: re}, nil
}

// match reports whether the normalized repository matches the whole glob.
func (g glob) match(repo string) bool { return g.re.MatchString(repo) }

// lastSegment is the part of s after its last "/", where a tag would sit;
// a ":" earlier is a registry port.
func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}
