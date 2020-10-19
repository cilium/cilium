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

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// A NodeNameFilter filters on node name. An empty NodeNameFilter matches all
// node names.
//
// NodeNameFilters are different to other filters as they are applied at the
// node level, not at the individual flow level.
//
// Node names are hostnames optionally prefixed by a cluster name and a slash,
// for example "k8s1" and "test-cluster/node01.company.com". Patterns match node
// names (hostnames) and are similar to filename globs, for example "k8s*" and
// "test-cluster/*.company.com". Literal lowercase letters, digits, hyphens,
// dots, and forward slashes match themselves. A single star "*" matches zero or
// more lowercase letters, digits, and hyphens (i.e. one domain name component,
// everything except a forward slash or a dot). A double star "**" matches one
// or more domain name components. All other characters are invalid.
type NodeNameFilter struct {
	includeRegexp *regexp.Regexp
	excludeRegexp *regexp.Regexp
}

// NewNodeNameFilter returns a new NodeNameFilter with whitelist and blacklist.
func NewNodeNameFilter(include, exclude []*flowpb.FlowFilter) (*NodeNameFilter, error) {
	includeRegexp, err := compileNodeNamePatterns(include)
	if err != nil {
		return nil, err
	}
	excludeRegexp, err := compileNodeNamePatterns(exclude)
	if err != nil {
		return nil, err
	}

	// short path: if there are no filters then return nil to avoid an
	// allocation
	if includeRegexp == nil && excludeRegexp == nil {
		return nil, nil
	}

	return &NodeNameFilter{
		includeRegexp: includeRegexp,
		excludeRegexp: excludeRegexp,
	}, nil
}

// Match returns true if f matches nodeName.
func (f *NodeNameFilter) Match(nodeName string) bool {
	if f == nil {
		return true
	}
	if f.includeRegexp != nil && !f.includeRegexp.MatchString(nodeName) {
		return false
	}
	if f.excludeRegexp != nil && f.excludeRegexp.MatchString(nodeName) {
		return false
	}
	return true
}

// compileNodeNamePatterns returns a regular expression equivalent to the node
// patterns in flowFilters. If flowFilters contains no node patterns then it
// returns nil.
func compileNodeNamePatterns(flowFilters []*flowpb.FlowFilter) (*regexp.Regexp, error) {
	sb := strings.Builder{}
	sb.WriteString(`\A(?:`)
	n := 0
	for _, flowFilter := range flowFilters {
		for _, nodePattern := range flowFilter.GetNodeName() {
			n++
			if n > 1 {
				sb.WriteByte('|')
			}
			if err := appendNodeNamePatternRegexp(&sb, nodePattern); err != nil {
				return nil, err
			}
		}
	}
	if n == 0 {
		return nil, nil
	}
	sb.WriteString(`)\z`)
	return regexp.Compile(sb.String())
}

// appendNodeNamePatternRegexp appends the regular expression equivalent to
// nodePattern to sb.
func appendNodeNamePatternRegexp(sb *strings.Builder, nodeNamePattern string) error {
	for i := 0; i < len(nodeNamePattern); i++ {
		b := nodeNamePattern[i]
		switch {
		case b == '.':
			sb.WriteString(`\.`)
		case b == '*':
			if i < len(nodeNamePattern)-1 && nodeNamePattern[i+1] == '*' {
				i++
				sb.WriteString(`(?:[\-0-9a-z]+(?:\.(?:[\-0-9a-z]+))*)`)
			} else {
				sb.WriteString(`[\-0-9a-z]*`)
			}
		case b == '-':
			fallthrough
		case b == '/':
			fallthrough
		case '0' <= b && b <= '9':
			fallthrough
		case 'a' <= b && b <= 'z':
			sb.WriteByte(b)
		default:
			return fmt.Errorf("%q: invalid byte in node name pattern", b)
		}
	}
	return nil
}
