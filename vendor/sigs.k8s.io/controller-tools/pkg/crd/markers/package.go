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

package markers

import (
	"sigs.k8s.io/controller-tools/pkg/markers"
)

func init() {
	AllDefinitions = append(AllDefinitions,
		must(markers.MakeDefinition("groupName", markers.DescribesPackage, "")).
			WithHelp(markers.SimpleHelp("CRD", "specifies the API group name for this package.")),

		must(markers.MakeDefinition("versionName", markers.DescribesPackage, "")).
			WithHelp(markers.SimpleHelp("CRD", "overrides the API group version for this package (defaults to the package name).")),

		must(markers.MakeDefinition("kubebuilder:validation:Optional", markers.DescribesPackage, struct{}{})).
			WithHelp(markers.SimpleHelp("CRD validation", "specifies that all fields in this package are optional by default.")),

		must(markers.MakeDefinition("kubebuilder:validation:Required", markers.DescribesPackage, struct{}{})).
			WithHelp(markers.SimpleHelp("CRD validation", "specifies that all fields in this package are required by default.")),

		must(markers.MakeDefinition("kubebuilder:skip", markers.DescribesPackage, struct{}{})).
			WithHelp(markers.SimpleHelp("CRD", "don't consider this package as an API version.")),
	)
}
