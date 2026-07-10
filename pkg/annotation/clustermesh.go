// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import (
	"fmt"
	"strings"
)

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

func GetAnnotationServiceAffinity(obj annotatedObject) (string, error) {
	// The ServiceAffinity annotation is ignored if the service is not declared as global.
	if !GetAnnotationIncludeExternal(obj) {
		return ServiceAffinityNone, nil
	}

	if value, ok := Get(obj, ServiceAffinity, ServiceAffinityAlias); ok {
		switch strings.ToLower(value) {
		case "none", "":
			return ServiceAffinityNone, nil
		case "local":
			return ServiceAffinityLocal, nil
		case "remote":
			return ServiceAffinityRemote, nil
		default:
			return ServiceAffinityNone, fmt.Errorf("unrecognized service affinity value: %q", value)
		}
	}

	return ServiceAffinityNone, nil
}
