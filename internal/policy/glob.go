package policy

import (
	"fmt"
	"regexp"
	"strings"
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
	if strings.ContainsAny(pattern, "@") || strings.Contains(lastSegment(pattern), ":") {
		return glob{}, fmt.Errorf("image glob %q must not include a tag or digest; verification is by digest", pattern)
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '*' && i+1 < len(pattern) && pattern[i+1] == '*':
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
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
