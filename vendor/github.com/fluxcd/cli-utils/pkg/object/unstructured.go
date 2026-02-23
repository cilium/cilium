// Copyright 2021 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0
//

package object

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/kustomize/kyaml/kio/kioutil"
)

var (
	namespaceGK = schema.GroupKind{Group: "", Kind: "Namespace"}
	crdGK       = schema.GroupKind{Group: "apiextensions.k8s.io", Kind: "CustomResourceDefinition"}
)

// UnstructuredSetToObjMetadataSet converts a UnstructuredSet to a ObjMetadataSet.
func UnstructuredSetToObjMetadataSet(objs UnstructuredSet) ObjMetadataSet {
	objMetas := make([]ObjMetadata, len(objs))
	for i, obj := range objs {
		objMetas[i] = UnstructuredToObjMetadata(obj)
	}
	return objMetas
}

// UnstructuredToObjMetadata extracts the identifying information from an
// Unstructured object and returns it as ObjMetadata object.
func UnstructuredToObjMetadata(obj *unstructured.Unstructured) ObjMetadata {
	return ObjMetadata{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
		GroupKind: obj.GroupVersionKind().GroupKind(),
	}
}

// IsKindNamespace returns true if the passed Unstructured object is
// GroupKind == Core/Namespace (no version checked); false otherwise.
func IsKindNamespace(u *unstructured.Unstructured) bool {
	if u == nil {
		return false
	}
	gvk := u.GroupVersionKind()
	return namespaceGK == gvk.GroupKind()
}

// IsNamespaced returns true if the passed Unstructured object
// is namespace-scoped (not cluster-scoped); false otherwise.
func IsNamespaced(u *unstructured.Unstructured) bool {
	if u == nil {
		return false
	}
	return u.GetNamespace() != ""
}

// IsNamespace returns true if the passed Unstructured object
// is Namespace in the core (empty string) group.
func IsNamespace(u *unstructured.Unstructured) bool {
	if u == nil {
		return false
	}
	gvk := u.GroupVersionKind()
	// core group, any version
	return gvk.Group == "" && gvk.Kind == "Namespace"
}

// IsCRD returns true if the passed Unstructured object has
// GroupKind == Extensions/CustomResourceDefinition; false otherwise.
func IsCRD(u *unstructured.Unstructured) bool {
	if u == nil {
		return false
	}
	gvk := u.GroupVersionKind()
	return crdGK == gvk.GroupKind()
}

// GetCRDGroupKind returns the GroupKind stored in the passed
// Unstructured CustomResourceDefinition and true if the passed object
// is a CRD.
func GetCRDGroupKind(u *unstructured.Unstructured) (schema.GroupKind, bool) {
	emptyGroupKind := schema.GroupKind{Group: "", Kind: ""}
	if u == nil {
		return emptyGroupKind, false
	}
	group, found, err := unstructured.NestedString(u.Object, "spec", "group")
	if found && err == nil {
		kind, found, err := unstructured.NestedString(u.Object, "spec", "names", "kind")
		if found && err == nil {
			return schema.GroupKind{Group: group, Kind: kind}, true
		}
	}
	return emptyGroupKind, false
}

// UnknownTypeError captures information about a type for which no information
// could be found in the cluster or among the known CRDs.
type UnknownTypeError struct {
	GroupVersionKind schema.GroupVersionKind
}

func (e *UnknownTypeError) Error() string {
	return fmt.Sprintf("unknown resource type: %q", e.GroupVersionKind.String())
}

// LookupResourceScope tries to look up the scope of the type of the provided
// resource, looking at both the types known to the cluster (through the
// RESTMapper) and the provided CRDs. If no information about the type can
// be found, an UnknownTypeError wil be returned.
func LookupResourceScope(u *unstructured.Unstructured, crds []*unstructured.Unstructured, mapper meta.RESTMapper) (meta.RESTScope, error) {
	gvk := u.GroupVersionKind()
	// First see if we can find the type (and the scope) in the cluster through
	// the RESTMapper.
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err == nil {
		// If we find the type in the cluster, we just look up the scope there.
		return mapping.Scope, nil
	}
	// Not finding a match is not an error here, so only error out for other
	// error types.
	if !meta.IsNoMatchError(err) {
		return nil, err
	}

	// If we couldn't find the type in the cluster, check if we find a
	// match in any of the provided CRDs.
	for _, crd := range crds {
		group, found, err := NestedField(crd.Object, "spec", "group")
		if err != nil {
			return nil, err
		}
		if !found || group == "" {
			return nil, NotFound([]interface{}{"spec", "group"}, group)
		}
		kind, found, err := NestedField(crd.Object, "spec", "names", "kind")
		if err != nil {
			return nil, err
		}
		if !found || kind == "" {
			return nil, NotFound([]interface{}{"spec", "kind"}, group)
		}
		if gvk.Kind != kind || gvk.Group != group {
			continue
		}
		versionDefined, err := crdDefinesVersion(crd, gvk.Version)
		if err != nil {
			return nil, err
		}
		if !versionDefined {
			return nil, &UnknownTypeError{
				GroupVersionKind: gvk,
			}
		}
		scopeName, _, err := NestedField(crd.Object, "spec", "scope")
		if err != nil {
			return nil, err
		}
		switch scopeName {
		case "Namespaced":
			return meta.RESTScopeNamespace, nil
		case "Cluster":
			return meta.RESTScopeRoot, nil
		default:
			return nil, Invalid([]interface{}{"spec", "scope"}, scopeName,
				"expected Namespaced or Cluster")
		}
	}
	return nil, &UnknownTypeError{
		GroupVersionKind: gvk,
	}
}

func crdDefinesVersion(crd *unstructured.Unstructured, version string) (bool, error) {
	versions, found, err := NestedField(crd.Object, "spec", "versions")
	if err != nil {
		return false, err
	}
	if !found {
		return false, NotFound([]interface{}{"spec", "versions"}, versions)
	}
	versionsSlice, ok := versions.([]interface{})
	if !ok {
		return false, InvalidType([]interface{}{"spec", "versions"}, versions, "[]interface{}")
	}
	if len(versionsSlice) == 0 {
		return false, Invalid([]interface{}{"spec", "versions"}, versionsSlice, "must not be empty")
	}
	for i := range versionsSlice {
		name, found, err := NestedField(crd.Object, "spec", "versions", i, "name")
		if err != nil {
			return false, err
		}
		if !found {
			return false, NotFound([]interface{}{"spec", "versions", i, "name"}, name)
		}
		if name == version {
			return true, nil
		}
	}
	return false, nil
}

// StripKyamlAnnotations removes any path and index annotations from the
// unstructured resource.
func StripKyamlAnnotations(u *unstructured.Unstructured) {
	annos := u.GetAnnotations()
	delete(annos, kioutil.PathAnnotation)
	delete(annos, kioutil.LegacyPathAnnotation) //nolint:staticcheck
	delete(annos, kioutil.IndexAnnotation)
	delete(annos, kioutil.LegacyIndexAnnotation) //nolint:staticcheck
	u.SetAnnotations(annos)
}
