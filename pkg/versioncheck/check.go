// Copyright 2018 Authors of Cilium
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

// Package versioncheck provides utility wrappers for go-version, allowing the
// constraints to be used as global variables.
package versioncheck

import (
	"fmt"

	go_version "github.com/hashicorp/go-version"
)

// MustCompile wraps go-version.NewConstraint, panicing when an error is
// returns (this occurs when the constraint cannot be parsed).
// It is intended to be use similar to re.MustCompile, to ensure unparseable
// constraints are caught in testing.
func MustCompile(constraint string) go_version.Constraints {
	verCheck, err := Compile(constraint)
	if err != nil {
		panic(fmt.Errorf("cannot compile go-version constraint '%s' %s", constraint, err))
	}
	return verCheck
}

// Compile trivially wraps go-version.NewConstraint, returning the constraint
// and error
func Compile(constraint string) (go_version.Constraints, error) {
	return go_version.NewConstraint(constraint)
}
