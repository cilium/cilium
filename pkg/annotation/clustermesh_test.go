// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetAnnotationIncludeExternal(t *testing.T) {
	obj := &object{}
	require.False(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "True"},
	}
	require.True(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "false"},
	}
	require.False(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: ""},
	}
	require.False(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalServiceAlias: "True"},
	}
	require.True(t, GetAnnotationIncludeExternal(obj))
}

func TestGetAnnotationShared(t *testing.T) {
	obj := &object{}
	require.False(t, GetAnnotationShared(obj))
	obj = &object{
		Annotations: map[string]string{GlobalService: "true"},
	}
	require.True(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{SharedService: "true"},
	}
	require.False(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", SharedService: "True"},
	}
	require.True(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", SharedService: "false"},
	}
	require.False(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", SharedServiceAlias: "false"},
	}
	require.False(t, GetAnnotationShared(obj))
}

func TestGetAnnotationServiceAffinity(t *testing.T) {
	obj := &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinity: "local"},
	}
	require.Equal(t, ServiceAffinityLocal, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinity: "remote"},
	}
	require.Equal(t, ServiceAffinityRemote, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinityAlias: "local"},
	}
	require.Equal(t, ServiceAffinityLocal, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{ServiceAffinity: "remote"},
	}
	require.Equal(t, ServiceAffinityNone, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{},
	}
	require.Equal(t, ServiceAffinityNone, GetAnnotationServiceAffinity(obj))
}

func TestGetAnnotationIncludeExternalWithNamespaceFilter(t *testing.T) {
	obj := &object{
		Annotations: map[string]string{},
	}

	isGlobalNamespace := func(namespace string) bool {
		return namespace == "production"
	}
	isFilteringActive := func() bool {
		return true
	}

	// Service without global annotation should not be global
	require.False(t, GetAnnotationIncludeExternalWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActive))
	require.False(t, GetAnnotationIncludeExternalWithNamespaceFilter(obj, "default", isGlobalNamespace, isFilteringActive))

	// Service with global annotation in global namespace should be global
	obj.Annotations = map[string]string{GlobalService: "true"}
	require.True(t, GetAnnotationIncludeExternalWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActive))

	// Service with global annotation in non-global namespace should not be global
	require.False(t, GetAnnotationIncludeExternalWithNamespaceFilter(obj, "default", isGlobalNamespace, isFilteringActive))

	// When filtering is not active, namespace should not matter
	isFilteringActiveOff := func() bool {
		return false
	}
	require.True(t, GetAnnotationIncludeExternalWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActiveOff))
	require.True(t, GetAnnotationIncludeExternalWithNamespaceFilter(obj, "default", isGlobalNamespace, isFilteringActiveOff))

	// Service without global annotation should not be global even when filtering is off
	obj.Annotations = map[string]string{}
	require.False(t, GetAnnotationIncludeExternalWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActiveOff))
}

func TestGetAnnotationServiceAffinityWithNamespaceFilter(t *testing.T) {
	obj := &object{
		Annotations: map[string]string{},
	}

	isGlobalNamespace := func(namespace string) bool {
		return namespace == "production"
	}
	isFilteringActive := func() bool {
		return true
	}

	// Service without global annotation should return ServiceAffinityNone
	require.Equal(t, ServiceAffinityNone, GetAnnotationServiceAffinityWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActive))

	// Service with global annotation but in non-global namespace should return ServiceAffinityNone
	obj.Annotations = map[string]string{GlobalService: "true"}
	require.Equal(t, ServiceAffinityNone, GetAnnotationServiceAffinityWithNamespaceFilter(obj, "default", isGlobalNamespace, isFilteringActive))

	// Service with global annotation in global namespace should return affinity
	obj.Annotations = map[string]string{GlobalService: "true", ServiceAffinity: ServiceAffinityLocal}
	require.Equal(t, ServiceAffinityLocal, GetAnnotationServiceAffinityWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActive))

	// Change affinity
	obj.Annotations[ServiceAffinity] = ServiceAffinityRemote
	require.Equal(t, ServiceAffinityRemote, GetAnnotationServiceAffinityWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActive))

	// No affinity annotation should return ServiceAffinityNone
	delete(obj.Annotations, ServiceAffinity)
	require.Equal(t, ServiceAffinityNone, GetAnnotationServiceAffinityWithNamespaceFilter(obj, "production", isGlobalNamespace, isFilteringActive))
}
