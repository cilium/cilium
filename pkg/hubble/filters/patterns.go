// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// fqdnRegexpStr matches an FQDN, inluding underscores.
	// FIXME this should not match components that begin or end with hyphens, e.g. -foo-
	fqdnRegexpStr = `(?:[-0-9_a-z]+(?:\.[-0-9_a-z]+)*)`
	_             = regexp.MustCompile(fqdnRegexpStr) // compile regexp to ensure that it is valid

	errEmptyPattern                  = errors.New("empty pattern")
	errMultipleTrailingDotsInPattern = errors.New("multiple trailing dots in pattern")
	errTooManySlashesInPattern       = errors.New("too many slashes in pattern")
)

// canonicalizeFQDNPattern canonicalizes fqdnPattern by trimming space, trimming
// up to one trailing dot, and converting it to lowercase.
func canonicalizeFQDNPattern(fqdnPattern string) string {
	fqdnPattern = strings.TrimSpace(fqdnPattern)
	fqdnPattern = strings.TrimSuffix(fqdnPattern, ".")
	fqdnPattern = strings.ToLower(fqdnPattern)
	return fqdnPattern
}

// appendFQDNPatternRegexp appends the regular expression equivalent to
// fqdnPattern to sb.
func appendFQDNPatternRegexp(sb *strings.Builder, fqdnPattern string) error {
	fqdnPattern = canonicalizeFQDNPattern(fqdnPattern)
	switch {
	case fqdnPattern == "":
		return errEmptyPattern
	case strings.HasSuffix(fqdnPattern, "."):
		return errMultipleTrailingDotsInPattern
	}
	for _, r := range fqdnPattern {
		switch {
		case r == '.':
			sb.WriteString(`\.`)
		case r == '*':
			sb.WriteString(`[-.0-9a-z]*`)
		case r == '-':
			fallthrough
		case '0' <= r && r <= '9':
			fallthrough
		case r == '_':
			fallthrough
		case 'a' <= r && r <= 'z':
			sb.WriteRune(r)
		default:
			return fmt.Errorf("%q: invalid rune in pattern", r)
		}
	}
	return nil
}

// appendNodeNamePatternRegexp appends the regular expression equivalent to
// nodeNamePattern to sb. The returned regular expression matches node names
// that include a cluster name.
//
// Node name patterns consist of a cluster pattern element and a node pattern
// element separated by a forward slash. Each element is an FQDN pattern, with
// an empty pattern matching everything. If there is no forward slash then the
// pattern is treated as a node pattern and matches all clusters.
func appendNodeNamePatternRegexp(sb *strings.Builder, nodeNamePattern string) error {
	if nodeNamePattern == "" {
		return errEmptyPattern
	}
	clusterPattern := ""
	nodePattern := ""
	elems := strings.Split(nodeNamePattern, "/")
	switch len(elems) {
	case 1:
		nodePattern = elems[0]
	case 2:
		clusterPattern = elems[0]
		nodePattern = elems[1]
	default:
		return errTooManySlashesInPattern
	}

	if clusterPattern == "" {
		sb.WriteString(fqdnRegexpStr)
	} else if err := appendFQDNPatternRegexp(sb, clusterPattern); err != nil {
		return err
	}
	sb.WriteByte('/')
	if nodePattern == "" {
		sb.WriteString(fqdnRegexpStr)
	} else if err := appendFQDNPatternRegexp(sb, nodePattern); err != nil {
		return err
	}
	return nil
}

// compileFQDNPattern returns a regular expression equivalent to the FQDN
// patterns in fqdnPatterns.
func compileFQDNPattern(fqdnPatterns []string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteString(`\A(?:`)
	for i, fqdnPattern := range fqdnPatterns {
		if i > 0 {
			sb.WriteByte('|')
		}
		if err := appendFQDNPatternRegexp(&sb, fqdnPattern); err != nil {
			return nil, err
		}
	}
	sb.WriteString(`)\z`)
	return regexp.Compile(sb.String())
}

// compileNodeNamePattern returns a regular expression equivalent to the node
// name patterns in nodeNamePatterns.
func compileNodeNamePattern(nodeNamePatterns []string) (*regexp.Regexp, error) {
	sb := strings.Builder{}
	sb.WriteString(`\A(?:`)
	for i, nodeNamePattern := range nodeNamePatterns {
		if i > 0 {
			sb.WriteByte('|')
		}
		if err := appendNodeNamePatternRegexp(&sb, nodeNamePattern); err != nil {
			return nil, err
		}
	}
	sb.WriteString(`)\z`)
	return regexp.Compile(sb.String())
}
