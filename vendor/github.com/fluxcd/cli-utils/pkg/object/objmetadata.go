// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0
//
// ObjMetadata is the minimal set of information to
// uniquely identify an object. The four fields are:
//
//   Group/Kind (NOTE: NOT version)
//   Namespace
//   Name
//
// We specifically do not use the "version", because
// the APIServer does not recognize a version as a
// different resource. This metadata is used to identify
// resources for pruning and teardown.

package object

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// Separates inventory fields. This string is allowable as a
	// ConfigMap key, but it is not allowed as a character in
	// resource name.
	fieldSeparator = "_"
	// Transform colons in the RBAC resource names to double
	// underscore.
	colonTranscoded = "__"
)

var (
	NilObjMetadata = ObjMetadata{}
)

// RBACGroupKind is a map of the RBAC resources. Needed since name validation
// is different than other k8s resources.
var RBACGroupKind = map[schema.GroupKind]bool{
	{Group: rbacv1.GroupName, Kind: "Role"}:               true,
	{Group: rbacv1.GroupName, Kind: "ClusterRole"}:        true,
	{Group: rbacv1.GroupName, Kind: "RoleBinding"}:        true,
	{Group: rbacv1.GroupName, Kind: "ClusterRoleBinding"}: true,
}

// ObjMetadata organizes and stores the indentifying information
// for an object. This struct (as a string) is stored in a
// inventory object to keep track of sets of applied objects.
type ObjMetadata struct {
	Namespace string
	Name      string
	GroupKind schema.GroupKind
}

// ParseObjMetadata takes a string, splits it into its four fields,
// and returns an ObjMetadata struct storing the four fields.
// Example inventory string:
//
//	test-namespace_test-name_apps_ReplicaSet
//
// Returns an error if unable to parse and create the ObjMetadata struct.
//
// NOTE: name field can contain double underscore (__), which represents
// a colon. RBAC resources can have this additional character (:) in their name.
func ParseObjMetadata(s string) (ObjMetadata, error) {
	// Parse first field namespace
	index := strings.Index(s, fieldSeparator)
	if index == -1 {
		return NilObjMetadata, fmt.Errorf("unable to parse stored object metadata: %s", s)
	}
	namespace := s[:index]
	s = s[index+1:]
	// Next, parse last field kind
	index = strings.LastIndex(s, fieldSeparator)
	if index == -1 {
		return NilObjMetadata, fmt.Errorf("unable to parse stored object metadata: %s", s)
	}
	kind := s[index+1:]
	s = s[:index]
	// Next, parse next to last field group
	index = strings.LastIndex(s, fieldSeparator)
	if index == -1 {
		return NilObjMetadata, fmt.Errorf("unable to parse stored object metadata: %s", s)
	}
	group := s[index+1:]
	// Finally, second field name. Name may contain colon transcoded as double underscore.
	name := s[:index]
	name = strings.ReplaceAll(name, colonTranscoded, ":")
	// Check that there are no extra fields by search for fieldSeparator.
	if strings.Contains(name, fieldSeparator) {
		return NilObjMetadata, fmt.Errorf("too many fields within: %s", s)
	}
	// Create the ObjMetadata object from the four parsed fields.
	id := ObjMetadata{
		Namespace: namespace,
		Name:      name,
		GroupKind: schema.GroupKind{
			Group: group,
			Kind:  kind,
		},
	}
	return id, nil
}

// Equals compares two ObjMetadata and returns true if they are equal. This does
// not contain any special treatment for the extensions API group.
func (o *ObjMetadata) Equals(other *ObjMetadata) bool {
	if other == nil {
		return false
	}
	return *o == *other
}

// String create a string version of the ObjMetadata struct. For RBAC resources,
// the "name" field transcodes ":" into double underscore for valid storing
// as the label of a ConfigMap.
func (o ObjMetadata) String() string {
	name := o.Name
	if _, exists := RBACGroupKind[o.GroupKind]; exists {
		name = strings.ReplaceAll(name, ":", colonTranscoded)
	}
	return fmt.Sprintf("%s%s%s%s%s%s%s",
		o.Namespace, fieldSeparator,
		name, fieldSeparator,
		o.GroupKind.Group, fieldSeparator,
		o.GroupKind.Kind)
}

// RuntimeToObjMeta extracts the object metadata information from a
// runtime.Object and returns it as ObjMetadata.
func RuntimeToObjMeta(obj runtime.Object) (ObjMetadata, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return NilObjMetadata, err
	}
	id := ObjMetadata{
		Namespace: accessor.GetNamespace(),
		Name:      accessor.GetName(),
		GroupKind: obj.GetObjectKind().GroupVersionKind().GroupKind(),
	}
	return id, nil
}
