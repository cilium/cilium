// Copyright 2018-2019 Authors of Cilium
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

package checker

import (
	"reflect"

	"github.com/cilium/cilium/pkg/comparator"

	"gopkg.in/check.v1"
)

type diffChecker struct {
	*check.CheckerInfo
}

// DeepEquals is a GoCheck checker that does a diff between two objects and
// pretty-prints any difference between the two. It can act as a substitute
// for DeepEquals.
var (
	defaultParams               = []string{"obtained", "expected"}
	DeepEquals    check.Checker = &diffChecker{
		&check.CheckerInfo{Name: "Diff", Params: defaultParams},
	}
)

// Check performs a diff between two objects provided as parameters, and
// returns either true if the objects are identical, or false otherwise. If
// it returns false, it also returns the unified diff between the expected
// and obtained output.
func (checker *diffChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if len(params) != 2 || len(names) != 2 {
		return false, "params and names must be of length 2"
	}

	if reflect.DeepEqual(params[0], params[1]) {
		return true, ""
	}

	return false, comparator.CompareWithNames(params[0], params[1], names[0], names[1])
}

// DeepEqual tests whether two parameters are deeply equal, and returns true if
// they are. If the objects are not deeply equal, then the second return value
// includes a json representation of the difference between the parameters.
func DeepEqual(params ...interface{}) (bool, string) {
	return DeepEquals.Check(params, defaultParams)
}
