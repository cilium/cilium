// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"fmt"
	"regexp"
	"strings"
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
		return fmt.Errorf("empty pattern")
	case strings.HasSuffix(fqdnPattern, "."):
		return fmt.Errorf("multiple trailing dots")
	}
	for _, r := range fqdnPattern {
		switch {
		case r == '.':
			sb.WriteString(`\.`)
		case r == '*':
			sb.WriteString(`[-\.0-9a-z]*`)
		case r == '-':
			fallthrough
		case '0' <= r && r <= '9':
			fallthrough
		case 'a' <= r && r <= 'z':
			sb.WriteRune(r)
		default:
			return fmt.Errorf("%q: invalid rune in pattern", r)
		}
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
