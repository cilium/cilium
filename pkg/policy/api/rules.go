// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package api

import (
	"fmt"
	"strings"
)

// Rules is a collection of api.Rule.
//
// All rules must be evaluated in order to come to a conclusion. While
// it is sufficient to have a single fromEndpoints rule match, none of
// the fromRequires may be violated at the same time.
// +deepequal-gen:private-method=true
type Rules []*Rule

func (rs Rules) String() string {
	strRules := make([]string, 0, len(rs))

	for _, r := range rs {
		strRules = append(strRules, fmt.Sprintf("%+v", r))
	}

	return "[" + strings.Join(strRules, ",\n") + "]"
}

// DeepEqual is a deepequal function, deeply comparing the
// receiver with other. the receiver must be non-nil.
func (rs *Rules) DeepEqual(other *Rules) bool {
	switch {
	case (rs == nil) != (other == nil):
		return false
	case (rs == nil) && (other == nil):
		return true
	}
	return rs.deepEqual(other)
}
