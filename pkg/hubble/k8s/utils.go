// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package k8s

import (
	"strings"
)

// ParseNamespaceName returns the object's namespace and name. If namespace is
// not specified, the namespace "default" is returned.
func ParseNamespaceName(namespaceName string) (string, string) {
	nsName := strings.Split(namespaceName, "/")
	ns := nsName[0]
	switch {
	case len(nsName) > 1:
		return ns, nsName[1]
	case ns == "":
		return "", ""
	default:
		return "default", ns
	}
}
