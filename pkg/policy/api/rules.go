// Copyright 2016-2019 Authors of Cilium
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

package api

import (
	"fmt"
	"reflect"
	"strings"
)

// Rules is a collection of api.Rule.
//
// All rules must be evaluated in order to come to a conclusion. While
// it is sufficient to have a single fromEndpoints rule match, none of
// the fromRequires may be violated at the same time.
type Rules []*Rule

func (rs Rules) String() string {
	strRules := make([]string, 0, len(rs))

	for _, r := range rs {
		strRules = append(strRules, fmt.Sprintf("%+v", r))
	}

	return "[" + strings.Join(strRules, ",\n") + "]"
}

// DeepEquals returns true if the specified rules are deeply the same.
func (rs Rules) DeepEquals(rs2 Rules) bool {
	return reflect.DeepEqual(rs, rs2)
}
