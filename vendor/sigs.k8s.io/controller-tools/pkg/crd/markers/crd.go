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
	"net/url"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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

	must(markers.MakeDefinition("kubebuilder:deprecatedversion", markers.DescribesType, DeprecatedVersion{})).
		WithHelp(DeprecatedVersion{}.Help()),

	must(markers.MakeDefinition("kubebuilder:metadata", markers.DescribesType, Metadata{})).
		WithHelp(Metadata{}.Help()),

	must(markers.MakeDefinition("kubebuilder:selectablefield", markers.DescribesType, SelectableField{})).
		WithHelp(SelectableField{}.Help()),

	must(markers.MakeDefinition("kubebuilder:externalDocs", markers.DescribesField, ExternalDocs{})).
		WithHelp(ExternalDocs{}.Help()),
	must(markers.MakeDefinition("kubebuilder:externalDocs", markers.DescribesType, ExternalDocs{})).
		WithHelp(ExternalDocs{}.Help()),
}

// TODO: categories and singular used to be annotations types
// TODO: doc

func init() {
	AllDefinitions = append(AllDefinitions, CRDMarkers...)
}

// +controllertools:marker:generateHelp:category=CRD

// SubresourceStatus enables the "/status" subresource on a CRD.
//
// The status subresource allows you to update the status field separately from the rest
// of the resource spec, and prevents updates to the status subresource when updating the root object.
// This is useful for separating user-provided spec from system-provided status.
//
// Example:
//
//	// +kubebuilder:subresource:status
//	type MyCRD struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	    Spec   MyCRDSpec
//	    Status MyCRDStatus
//	}
type SubresourceStatus struct{}

func (s SubresourceStatus) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
	var subresources *apiextensionsv1.CustomResourceSubresources
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		if ver.Subresources == nil {
			ver.Subresources = &apiextensionsv1.CustomResourceSubresources{}
		}
		subresources = ver.Subresources
		break
	}
	if subresources == nil {
		return fmt.Errorf("status subresource applied to version %q not in CRD", version)
	}
	subresources.Status = &apiextensionsv1.CustomResourceSubresourceStatus{}
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// SubresourceScale enables the "/scale" subresource on a CRD.
//
// The scale subresource allows you to use `kubectl scale` and the HorizontalPodAutoscaler with your CRD.
//
// Example:
//
//	// +kubebuilder:subresource:scale:specpath=.spec.replicas,statuspath=.status.replicas,selectorpath=.status.selector
//	type MyCRD struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	    Spec MyCRDSpec
//	    Status MyCRDStatus
//	}
type SubresourceScale struct {
	// marker names are leftover legacy cruft

	// SpecPath specifies the jsonpath to the replicas field for the scale's spec.
	// This is where the desired number of replicas is stored (typically .spec.replicas).
	SpecPath string `marker:"specpath"`

	// StatusPath specifies the jsonpath to the replicas field for the scale's status.
	// This is where the actual number of replicas is stored (typically .status.replicas).
	StatusPath string `marker:"statuspath"`

	// SelectorPath specifies the jsonpath to the pod label selector field for the scale's status.
	//
	// The selector field must be the *string* form (serialized form) of a selector.
	// Setting a pod label selector is necessary for your type to work with the HorizontalPodAutoscaler.
	// This is typically .status.selector.
	SelectorPath *string `marker:"selectorpath"`
}

func (s SubresourceScale) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
	var subresources *apiextensionsv1.CustomResourceSubresources
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		if ver.Subresources == nil {
			ver.Subresources = &apiextensionsv1.CustomResourceSubresources{}
		}
		subresources = ver.Subresources
		break
	}
	if subresources == nil {
		return fmt.Errorf("scale subresource applied to version %q not in CRD", version)
	}
	subresources.Scale = &apiextensionsv1.CustomResourceSubresourceScale{
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
//
// Example:
//
//	// +kubebuilder:storageversion
//	type MyCRDv2 struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	    Spec MyCRDSpec
//	}
type StorageVersion struct{}

func (s StorageVersion) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
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
//
// Example:
//
//	// +kubebuilder:skipversion
//	type MyCRDInternal struct {
//	    // internal version not served by API
//	}
type SkipVersion struct{}

func (s SkipVersion) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
	if version == "" {
		// single-version, this is an invalid state
		return fmt.Errorf("cannot skip a version if there is only a single version")
	}
	var versions []apiextensionsv1.CustomResourceDefinitionVersion
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
//
// This allows you to customize which columns are shown when users run `kubectl get` on your CRD.
//
// Example:
//
//	// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
//	// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
//	type MyCRD struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	}
type PrintColumn struct {
	// Name specifies the name of the column as it will appear in the header.
	Name string

	// Type indicates the type of the column.
	//
	// It may be any OpenAPI data type listed at
	// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types.
	// Common values: "string", "integer", "number", "boolean", "date".
	Type string

	// JSONPath specifies the jsonpath expression used to extract the value of the column.
	// The path is relative to the resource root. Example: `.status.phase` or `.spec.replicas`.
	JSONPath string `marker:"JSONPath"` // legacy cruft

	// Description specifies optional help text for this column.
	// Display behavior is client-dependent; see CustomResourceColumnDefinition in the Kubernetes API docs.
	Description string `marker:",optional"`

	// Format specifies the format of the column.
	//
	// It may be any OpenAPI data format corresponding to the type, listed at
	// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#data-types.
	Format string `marker:",optional"`

	// Priority indicates how important it is that this column be displayed.
	//
	// Lower priority (*higher* numbered) columns will be hidden if the terminal
	// width is too small. Priority 0 columns are always shown.
	Priority int32 `marker:",optional"`
}

func (s PrintColumn) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
	var columns *[]apiextensionsv1.CustomResourceColumnDefinition
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		if ver.Subresources == nil {
			ver.Subresources = &apiextensionsv1.CustomResourceSubresources{}
		}
		columns = &ver.AdditionalPrinterColumns
		break
	}
	if columns == nil {
		return fmt.Errorf("printer columns applied to version %q not in CRD", version)
	}

	*columns = append(*columns, apiextensionsv1.CustomResourceColumnDefinition{
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
//
// Example:
//
//	// +kubebuilder:resource:path=mycrdplural,singular=mycrdsingular,shortName=mc;mcrd,categories=all,scope=Namespaced
//	type MyCRD struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	}
type Resource struct {
	// Path specifies the plural "resource" for this CRD.
	//
	// It generally corresponds to a plural, lower-cased version of the Kind.
	// For example, if the Kind is "MyCRD", the path might be "mycrds".
	// See https://book.kubebuilder.io/cronjob-tutorial/gvks.html.
	Path string `marker:",optional"`

	// ShortName specifies aliases for this CRD.
	//
	// Short names are often used when people have work with your resource
	// over and over again.  For instance, "rs" for "replicaset" or
	// "crd" for customresourcedefinition. Multiple short names can be specified
	// separated by semicolons.
	ShortName []string `marker:",optional"`

	// Categories specifies which group aliases this resource is part of.
	//
	// Group aliases are used to work with groups of resources at once.
	// The most common one is "all" which covers about a third of the base
	// resources in Kubernetes, and is generally used for "user-facing" resources.
	// This allows users to run commands like `kubectl get all` to include your CRD.
	Categories []string `marker:",optional"`

	// Singular overrides the singular form of your resource.
	//
	// The singular form is otherwise defaulted off the plural (path).
	// This is used in API responses and `kubectl` output.
	Singular string `marker:",optional"`

	// Scope overrides the scope of the CRD (Cluster vs Namespaced).
	//
	// Scope defaults to "Namespaced".  Cluster-scoped ("Cluster") resources
	// don't exist in namespaces and are accessible from anywhere in the cluster.
	Scope string `marker:",optional"`
}

func (s Resource) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, _ string) error {
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
		crd.Scope = apiextensionsv1.NamespaceScoped
	default:
		crd.Scope = apiextensionsv1.ResourceScope(s.Scope)
	}

	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// UnservedVersion does not serve this version.
//
// This is useful if you need to drop support for a version in favor of a newer version.
// The version will still be stored in etcd if it's the storage version, but won't be
// served via the API.
//
// Example:
//
//	// +kubebuilder:unservedversion
//	type MyCRDv1alpha1 struct {
//	    // This version is no longer served
//	}
type UnservedVersion struct{}

func (s UnservedVersion) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
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

// +controllertools:marker:generateHelp:category=CRD

// DeprecatedVersion marks this version as deprecated.
//
// Deprecated versions show a warning message when used. This is useful for
// communicating to users that they should migrate to a newer version.
//
// Example:
//
//	// +kubebuilder:deprecatedversion:warning="v1alpha1 is deprecated; use v1 instead"
//	type MyCRDv1alpha1 struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	}
type DeprecatedVersion struct {
	// Warning message to be shown on the deprecated version.
	// This message is displayed to users when they interact with the deprecated version.
	Warning *string `marker:",optional"`
}

func (s DeprecatedVersion) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
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
		ver.Deprecated = true
		ver.DeprecationWarning = s.Warning
		break
	}
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// Metadata configures the additional annotations or labels for this CRD.
// For example adding annotation "api-approved.kubernetes.io" for a CRD with Kubernetes groups,
// or annotation "cert-manager.io/inject-ca-from-secret" for a CRD that needs CA injection.
//
// Example:
//
//	// +kubebuilder:metadata:annotations="api-approved.kubernetes.io/v1=https://github.com/myorg/myrepo/pull/123"
//	// +kubebuilder:metadata:labels="app=myapp"
//	type MyCRD struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	}
type Metadata struct {
	// Annotations will be added into the annotations of this CRD.
	// Format: "key=value". Multiple annotations can be specified by repeating the marker.
	Annotations []string `marker:",optional"`

	// Labels will be added into the labels of this CRD.
	// Format: "key=value". Multiple labels can be specified by repeating the marker.
	Labels []string `marker:",optional"`
}

func (s Metadata) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinition, _ string) error {
	if len(s.Annotations) > 0 {
		if crd.Annotations == nil {
			crd.Annotations = map[string]string{}
		}
		for _, str := range s.Annotations {
			kv := strings.SplitN(str, "=", 2)
			if len(kv) < 2 {
				return fmt.Errorf("annotation %s is not in 'xxx=xxx' format", str)
			}
			crd.Annotations[kv[0]] = kv[1]
		}
	}

	if len(s.Labels) > 0 {
		if crd.Labels == nil {
			crd.Labels = map[string]string{}
		}
		for _, str := range s.Labels {
			kv := strings.SplitN(str, "=", 2)
			crd.Labels[kv[0]] = kv[1]
		}
	}

	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// SelectableField adds a field that may be used with field selectors.
//
// Field selectors allow users to filter resources based on field values when listing.
// For example, `kubectl get mycrds --field-selector status.phase=Running`.
//
// Example:
//
//	// +kubebuilder:selectablefield:JSONPath=".status.phase"
//	type MyCRD struct {
//	    metav1.TypeMeta
//	    metav1.ObjectMeta
//	    Status MyCRDStatus
//	}
type SelectableField struct {
	// JSONPath specifies the jsonpath expression which is used to produce a field selector value.
	// The path is relative to the resource root. Example: `.status.phase`.
	JSONPath string `marker:"JSONPath"`
}

func (s SelectableField) ApplyToCRD(crd *apiextensionsv1.CustomResourceDefinitionSpec, version string) error {
	var selectableFields *[]apiextensionsv1.SelectableField
	for i := range crd.Versions {
		ver := &crd.Versions[i]
		if ver.Name != version {
			continue
		}
		selectableFields = &ver.SelectableFields
		break
	}
	if selectableFields == nil {
		return fmt.Errorf("selectable field applied to version %q not in CRD", version)
	}

	*selectableFields = append(*selectableFields, apiextensionsv1.SelectableField{
		JSONPath: s.JSONPath,
	})

	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// ExternalDocs specifies external documentation for this field or type.
//
// The url is required and must be a valid URL. The description is optional
// and provides a short description of the external documentation.
type ExternalDocs struct {
	// URL specifies the URL for the target documentation.
	URL string `marker:"url"`

	// Description is a short description of the target documentation.
	Description string `marker:",optional"`
}

func (m ExternalDocs) ApplyToSchema(ctx *SchemaContext, schema *apiextensionsv1.JSONSchemaProps) error {
	if _, err := url.ParseRequestURI(m.URL); err != nil {
		return fmt.Errorf("invalid url %q in kubebuilder:externalDocs marker: %w", m.URL, err)
	}
	schema.ExternalDocs = &apiextensionsv1.ExternalDocumentation{
		URL:         m.URL,
		Description: m.Description,
	}
	return nil
}
