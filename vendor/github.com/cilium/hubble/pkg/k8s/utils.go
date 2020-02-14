// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// ParseNamespaceNames returns the object's namespace and name. If namespace is
// not specified, the namespace "default" is returned.
func ParseNamespaceNames(namespaceNames []string) ([]string, []string) {
	pods := make([]string, 0, len(namespaceNames))
	nss := make([]string, 0, len(namespaceNames))

	for _, namespaceName := range namespaceNames {
		ns, pod := ParseNamespaceName(namespaceName)
		nss = append(nss, ns)
		pods = append(pods, pod)
	}

	return nss, pods
}
