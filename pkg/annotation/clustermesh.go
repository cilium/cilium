// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import "strings"

const (
	ServiceAffinityNone   = ""
	ServiceAffinityLocal  = "local"
	ServiceAffinityRemote = "remote"
)

func GetAnnotationIncludeExternal(obj annotatedObject) bool {
	if value, ok := Get(obj, GlobalService, GlobalServiceAlias); ok {
		return strings.ToLower(value) == "true"
	}

	return false
}

// GetAnnotationIncludeExternalWithNamespaceFilter checks both the global service annotation
// and whether the service resides in a global namespace when namespace filtering is active.
func GetAnnotationIncludeExternalWithNamespaceFilter(obj annotatedObject, namespace string, isGlobalNamespace func(string) bool, isFilteringActive func() bool) bool {
	// First check if service has the global annotation
	if value, ok := Get(obj, GlobalService, GlobalServiceAlias); !ok || strings.ToLower(value) != "true" {
		return false
	}

	// If namespace filtering is active, also check if service is in a global namespace
	if isFilteringActive != nil && isFilteringActive() {
		if isGlobalNamespace != nil && !isGlobalNamespace(namespace) {
			// Service is marked as global but not in a global namespace
			return false
		}
	}

	return true
}

func GetAnnotationShared(obj annotatedObject) bool {
	// The SharedService annotation is ignored if the service is not declared as global.
	if !GetAnnotationIncludeExternal(obj) {
		return false
	}

	if value, ok := Get(obj, SharedService, SharedServiceAlias); ok {
		return strings.ToLower(value) == "true"
	}

	// A global service is marked as shared by default.
	return true
}

func GetAnnotationServiceAffinity(obj annotatedObject) string {
	// The ServiceAffinity annotation is ignored if the service is not declared as global.
	if !GetAnnotationIncludeExternal(obj) {
		return ServiceAffinityNone
	}

	if value, ok := Get(obj, ServiceAffinity, ServiceAffinityAlias); ok {
		return strings.ToLower(value)
	}

	return ServiceAffinityNone
}
