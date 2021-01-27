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
	"fmt"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"sigs.k8s.io/controller-tools/pkg/markers"
)

// CRDMarkers lists all markers that directly modify the CRD (not validation
// schemas).
var CRDMarkers = []*definitionWithHelp{
	// TODO(directxman12): more detailed help
	must(markers.MakeDefinition("kubebuilder:subresource:status", markers.DescribesType, SubresourceStatus{})).
		WithHelp(SubresourceStatus{}.Help()),

	must(markers.MakeDefinition("kubebuilder:subresource:scale", markers.DescribesType, SubresourceScale{})).
		WithHelp(SubresourceScale{}.Help()),

	must(markers.MakeDefinition("kubebuilder:printcolumn", markers.DescribesType, PrintColumn{})).
		WithHelp(PrintColumn{}.Help()),

	must(markers.MakeDefinition("kubebuilder:resource", markers.DescribesType, Resource{})).
		WithHelp(Resource{}.Help()),

	must(markers.MakeDefinition("kubebuilder:storageversion", markers.DescribesType, StorageVersion{})).
		WithHelp(StorageVersion{}.Help()),

	must(markers.MakeDefinition("kubebuilder:skipversion", markers.DescribesType, SkipVersion{})).
		WithHelp(SkipVersion{}.Help()),

	must(markers.MakeDefinition("kubebuilder:unservedversion", markers.DescribesType, UnservedVersion{})).
		WithHelp(UnservedVersion{}.Help()),
}

// TODO: categories and singular used to be annotations types
// TODO: doc

func init() {
	AllDefinitions = append(AllDefinitions, CRDMarkers...)
}

// +controllertools:marker:generateHelp:category=CRD

// SubresourceStatus enables the "/status" subresource on a CRD.
type SubresourceStatus struct{}

func (s SubresourceStatus) ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error {
	var subresources *apiext.CustomResourceSubresources
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		if ver.Subresources == nil {
			ver.Subresources = &apiext.CustomResourceSubresources{}
		}
		subresources = ver.Subresources
		break
	}
	if subresources == nil {
		return fmt.Errorf("status subresource applied to version %q not in CRD", version)
	}
	subresources.Status = &apiext.CustomResourceSubresourceStatus{}
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// SubresourceScale enables the "/scale" subresource on a CRD.
type SubresourceScale struct {
	// marker names are leftover legacy cruft

	// SpecPath specifies the jsonpath to the replicas field for the scale's spec.
	SpecPath string `marker:"specpath"`

	// StatusPath specifies the jsonpath to the replicas field for the scale's status.
	StatusPath string `marker:"statuspath"`

	// SelectorPath specifies the jsonpath to the pod label selector field for the scale's status.
	//
	// The selector field must be the *string* form (serialized form) of a selector.
	// Setting a pod label selector is necessary for your type to work with the HorizontalPodAutoscaler.
	SelectorPath *string `marker:"selectorpath"`
}

func (s SubresourceScale) ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error {
	var subresources *apiext.CustomResourceSubresources
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		if ver.Subresources == nil {
			ver.Subresources = &apiext.CustomResourceSubresources{}
		}
		subresources = ver.Subresources
		break
	}
	if subresources == nil {
		return fmt.Errorf("scale subresource applied to version %q not in CRD", version)
	}
	subresources.Scale = &apiext.CustomResourceSubresourceScale{
		SpecReplicasPath:   s.SpecPath,
		StatusReplicasPath: s.StatusPath,
		LabelSelectorPath:  s.SelectorPath,
	}
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// StorageVersion marks this version as the "storage version" for the CRD for conversion.
//
// When conversion is enabled for a CRD (i.e. it's not a trivial-versions/single-version CRD),
// one version is set as the "storage version" to be stored in etcd.  Attempting to store any
// other version will result in conversion to the storage version via a conversion webhook.
type StorageVersion struct{}

func (s StorageVersion) ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error {
	if version == "" {
		// single-version, do nothing
		return nil
	}
	// multi-version
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		ver.Storage = true
		break
	}
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// SkipVersion removes the particular version of the CRD from the CRDs spec.
//
// This is useful if you need to skip generating and listing version entries
// for 'internal' resource versions, which typically exist if using the
// Kubernetes upstream conversion-gen tool.
type SkipVersion struct{}

func (s SkipVersion) ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error {
	if version == "" {
		// single-version, this is an invalid state
		return fmt.Errorf("cannot skip a version if there is only a single version")
	}
	var versions []apiext.CustomResourceDefinitionVersion
	// multi-version
	for i := range crd.Versions {
		ver := crd.Versions[i]
		if ver.Name == version {
			// skip the skipped version
			continue
		}
		versions = append(versions, ver)
	}
	crd.Versions = versions
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// PrintColumn adds a column to "kubectl get" output for this CRD.
type PrintColumn struct {
	// Name specifies the name of the column.
	Name string

	// Type indicates the type of the column.
	//
	// It may be any OpenAPI data type listed at
	// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types.
	Type string

	// JSONPath specifies the jsonpath expression used to extract the value of the column.
	JSONPath string `marker:"JSONPath"` // legacy cruft

	// Description specifies the help/description for this column.
	Description string `marker:",optional"`

	// Format specifies the format of the column.
	//
	// It may be any OpenAPI data format corresponding to the type, listed at
	// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types.
	Format string `marker:",optional"`

	// Priority indicates how important it is that this column be displayed.
	//
	// Lower priority (*higher* numbered) columns will be hidden if the terminal
	// width is too small.
	Priority int32 `marker:",optional"`
}

func (s PrintColumn) ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error {
	var columns *[]apiext.CustomResourceColumnDefinition
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		if ver.Subresources == nil {
			ver.Subresources = &apiext.CustomResourceSubresources{}
		}
		columns = &ver.AdditionalPrinterColumns
		break
	}
	if columns == nil {
		return fmt.Errorf("printer columns applied to version %q not in CRD", version)
	}

	*columns = append(*columns, apiext.CustomResourceColumnDefinition{
		Name:        s.Name,
		Type:        s.Type,
		JSONPath:    s.JSONPath,
		Description: s.Description,
		Format:      s.Format,
		Priority:    s.Priority,
	})

	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// Resource configures naming and scope for a CRD.
type Resource struct {
	// Path specifies the plural "resource" for this CRD.
	//
	// It generally corresponds to a plural, lower-cased version of the Kind.
	// See https://book.kubebuilder.io/cronjob-tutorial/gvks.html.
	Path string `marker:",optional"`

	// ShortName specifies aliases for this CRD.
	//
	// Short names are often used when people have work with your resource
	// over and over again.  For instance, "rs" for "replicaset" or
	// "crd" for customresourcedefinition.
	ShortName []string `marker:",optional"`

	// Categories specifies which group aliases this resource is part of.
	//
	// Group aliases are used to work with groups of resources at once.
	// The most common one is "all" which covers about a third of the base
	// resources in Kubernetes, and is generally used for "user-facing" resources.
	Categories []string `marker:",optional"`

	// Singular overrides the singular form of your resource.
	//
	// The singular form is otherwise defaulted off the plural (path).
	Singular string `marker:",optional"`

	// Scope overrides the scope of the CRD (Cluster vs Namespaced).
	//
	// Scope defaults to "Namespaced".  Cluster-scoped ("Cluster") resources
	// don't exist in namespaces.
	Scope string `marker:",optional"`
}

func (s Resource) ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error {
	if s.Path != "" {
		crd.Names.Plural = s.Path
	}
	if s.Singular != "" {
		crd.Names.Singular = s.Singular
	}
	crd.Names.ShortNames = s.ShortName
	crd.Names.Categories = s.Categories

	switch s.Scope {
	case "":
		crd.Scope = apiext.NamespaceScoped
	default:
		crd.Scope = apiext.ResourceScope(s.Scope)
	}

	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// UnservedVersion does not serve this version.
//
// This is useful if you need to drop support for a version in favor of a newer version.
type UnservedVersion struct{}

func (s UnservedVersion) ApplyToCRD(crd *apiext.CustomResourceDefinitionSpec, version string) error {
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		ver.Served = false
		break
	}
	return nil
}

// NB(directxman12): singular was historically distinct, so we keep it here for backwards compat
