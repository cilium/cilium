// Copyright 2016-2018 Authors of Cilium
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

package v3

// Rules is a collection of api.Rule.
//
// All rules must be evaluated in order to come to a conclusion. While
// it is sufficient to have a single fromEndpoints rule match, none of
// the fromRequires may be violated at the same time.
type Rules []*Rule

func (r *Rules) Sanitize() error {
	if r == nil {
		return nil
	}
	for _, v3Rule := range *r {
		err := v3Rule.Sanitize()
		if err != nil {
			return err
		}
	}
	return nil
}

// VersionRules is a wrapper for Rules to append the version number of the
// policy, when using cilium CLI.
type VersionRules struct {
	// Rules are the api rules used for this version.
	Rules `json:"rules"`

	// Version is the version of this policy type.
	Version string `json:"version"`
}
