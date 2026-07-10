/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package help

import (
	"strings"

	"sigs.k8s.io/controller-tools/pkg/markers"
)

// SortGroup knows how to sort and group marker definitions.
type SortGroup interface {
	// Compare is equivalent to the compare function from slices, and is used to sort the markers.
	Compare(*markers.Definition, *markers.Definition) int
	// Group returns the "group" that a given marker belongs to.
	Group(*markers.Definition, *markers.DefinitionHelp) string
}

var (
	// SortByCategory sorts the markers by name and groups them by their help category.
	SortByCategory = sortByCategory{}

	// SortByOption sorts by the generator that the option belongs to.
	SortByOption = optionsSort{}
)

type sortByCategory struct{}

func (sortByCategory) Group(_ *markers.Definition, help *markers.DefinitionHelp) string {
	if help == nil {
		return ""
	}
	return help.Category
}
func (sortByCategory) Compare(i, j *markers.Definition) int {
	return strings.Compare(j.Name, i.Name)
}

type optionsSort struct{}

func (optionsSort) Compare(i, j *markers.Definition) int {
	iParts := strings.Split(i.Name, ":")
	jParts := strings.Split(j.Name, ":")

	iGen := ""
	iRule := ""
	jGen := ""
	jRule := ""

	switch len(iParts) {
	case 1:
		iGen = iParts[0]
	// two means a default output rule, so ignore
	case 2:
		iRule = iParts[1]
	case 3:
		iGen = iParts[1]
		iRule = iParts[2]
	}
	switch len(jParts) {
	case 1:
		jGen = jParts[0]
	// two means a default output rule, so ignore
	case 2:
		jRule = jParts[1]
	case 3:
		jGen = jParts[1]
		jRule = jParts[2]
	}

	if iGen != jGen {
		return strings.Compare(iGen, jGen)
	}

	return strings.Compare(jRule, iRule)
}
func (optionsSort) Group(def *markers.Definition, _ *markers.DefinitionHelp) string {
	parts := strings.Split(def.Name, ":")

	switch len(parts) {
	case 1:
		if parts[0] == "paths" {
			return "generic"
		}
		return "generators"
	case 2:
		return "output rules (optionally as output:<generator>:...)"
	default:
		return ""
		// three means a marker-specific output rule, ignore
	}
}
