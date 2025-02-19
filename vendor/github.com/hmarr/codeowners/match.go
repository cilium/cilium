package codeowners

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type pattern struct {
	pattern             string
	regex               *regexp.Regexp
	leftAnchoredLiteral bool
}

// newPattern creates a new pattern struct from a gitignore-style pattern string
func newPattern(patternStr string) (pattern, error) {
	pat := pattern{pattern: patternStr}

	if !strings.ContainsAny(patternStr, "*?\\") && patternStr[0] == '/' {
		pat.leftAnchoredLiteral = true
	} else {
		patternRegex, err := buildPatternRegex(patternStr)
		if err != nil {
			return pattern{}, err
		}
		pat.regex = patternRegex
	}

	return pat, nil
}

// match tests if the path provided matches the pattern
func (p pattern) match(testPath string) (bool, error) {
	// Normalize Windows-style path separators to forward slashes
	testPath = filepath.ToSlash(testPath)

	if p.leftAnchoredLiteral {
		prefix := p.pattern

		// Strip the leading slash as we're anchored to the root already
		if prefix[0] == '/' {
			prefix = prefix[1:]
		}

		// If the pattern ends with a slash we can do a simple prefix match
		if prefix[len(prefix)-1] == '/' {
			return strings.HasPrefix(testPath, prefix), nil
		}

		// If the strings are the same length, check for an exact match
		if len(testPath) == len(prefix) {
			return testPath == prefix, nil
		}

		// Otherwise check if the test path is a subdirectory of the pattern
		if len(testPath) > len(prefix) && testPath[len(prefix)] == '/' {
			return testPath[:len(prefix)] == prefix, nil
		}

		// Otherwise the test path must be shorter than the pattern, so it can't match
		return false, nil
	}

	return p.regex.MatchString(testPath), nil
}

// buildPatternRegex compiles a new regexp object from a gitignore-style pattern string
func buildPatternRegex(pattern string) (*regexp.Regexp, error) {
	// Handle specific edge cases first
	switch {
	case strings.Contains(pattern, "***"):
		return nil, fmt.Errorf("pattern cannot contain three consecutive asterisks")
	case pattern == "":
		return nil, fmt.Errorf("empty pattern")
	case pattern == "/":
		// "/" doesn't match anything
		return regexp.Compile(`\A\z`)
	}

	segs := strings.Split(pattern, "/")

	if segs[0] == "" {
		// Leading slash: match is relative to root
		segs = segs[1:]
	} else {
		// No leading slash - check for a single segment pattern, which matches
		// relative to any descendent path (equivalent to a leading **/)
		if len(segs) == 1 || (len(segs) == 2 && segs[1] == "") {
			if segs[0] != "**" {
				segs = append([]string{"**"}, segs...)
			}
		}
	}

	if len(segs) > 1 && segs[len(segs)-1] == "" {
		// Trailing slash is equivalent to "/**"
		segs[len(segs)-1] = "**"
	}

	sep := "/"

	lastSegIndex := len(segs) - 1
	needSlash := false
	var re strings.Builder
	re.WriteString(`\A`)
	for i, seg := range segs {
		switch seg {
		case "**":
			switch {
			case i == 0 && i == lastSegIndex:
				// If the pattern is just "**" we match everything
				re.WriteString(`.+`)
			case i == 0:
				// If the pattern starts with "**" we match any leading path segment
				re.WriteString(`(?:.+` + sep + `)?`)
				needSlash = false
			case i == lastSegIndex:
				// If the pattern ends with "**" we match any trailing path segment
				re.WriteString(sep + `.*`)
			default:
				// If the pattern contains "**" we match zero or more path segments
				re.WriteString(`(?:` + sep + `.+)?`)
				needSlash = true
			}

		case "*":
			if needSlash {
				re.WriteString(sep)
			}

			// Regular wildcard - match any characters except the separator
			re.WriteString(`[^` + sep + `]+`)
			needSlash = true

		default:
			if needSlash {
				re.WriteString(sep)
			}

			escape := false
			for _, ch := range seg {
				if escape {
					escape = false
					re.WriteString(regexp.QuoteMeta(string(ch)))
					continue
				}

				// Other pathspec implementations handle character classes here (e.g.
				// [AaBb]), but CODEOWNERS doesn't support that so we don't need to
				switch ch {
				case '\\':
					escape = true
				case '*':
					// Multi-character wildcard
					re.WriteString(`[^` + sep + `]*`)
				case '?':
					// Single-character wildcard
					re.WriteString(`[^` + sep + `]`)
				default:
					// Regular character
					re.WriteString(regexp.QuoteMeta(string(ch)))
				}
			}

			if i == lastSegIndex {
				// As there's no trailing slash (that'd hit the '**' case), we
				// need to match descendent paths
				re.WriteString(`(?:` + sep + `.*)?`)
			}

			needSlash = true
		}
	}
	re.WriteString(`\z`)
	return regexp.Compile(re.String())
}
