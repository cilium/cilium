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
)

// SplitNodePath returns path without extension and the extension if any.
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
