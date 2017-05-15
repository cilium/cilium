// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
)

// SplitNodePath splits a policy node path into the path and name portion.
// Examples:
//   - "foo.bar"     => "foo", "bar"
//   - "foo.bar.baz" => "foo.bar", "baz"
//   - "foo"         => "foo", ""
//   - ""            => "", ""
func SplitNodePath(fullPath string) (string, string) {
	var extension = filepath.Ext(fullPath)
	if len(extension) > 0 {
		return fullPath[0 : len(fullPath)-len(extension)], extension[1:]
	}
	return fullPath[0 : len(fullPath)-len(extension)], extension
}

// JoinPath returns a joined path from a and b.
func JoinPath(a, b string) string {
	return a + NodePathDelimiter + b
}

// removeRootPrefix removes an eventual `root.` or `root` prefix from the path.
func removeRootPrefix(path string) string {
	if path == RootNodeName {
		return ""
	}
	cut := JoinPath(RootNodeName, "")
	if strings.HasPrefix(path, cut) {
		path = strings.TrimPrefix(path, cut)
	}
	return path
}

func removeRootK8sPrefixFromLabelArray(lblsIn labels.LabelArray) labels.LabelArray {
	lbl := make(labels.LabelArray, len(lblsIn))
	for i, v := range lblsIn {
		lbl[i] = labels.NewLabel(removeRootK8sPrefix(v.Key), v.Value, v.Source)
	}
	return lbl
}

// removeRootK8sPrefix removes an eventual `root.`, `root`, `k8s`, `k8s.`,
// `root.k8s.`, `root.k8s` prefix from the path.
func removeRootK8sPrefix(path string) string {
	path = removeRootPrefix(path)
	if path == k8s.DefaultPolicyParentPath {
		return ""
	}
	if strings.HasPrefix(path, k8s.DefaultPolicyParentPath) {
		return strings.TrimPrefix(path, k8s.DefaultPolicyParentPathPrefix)
	}
	return path
}
