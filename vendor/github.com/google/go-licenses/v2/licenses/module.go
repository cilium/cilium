// Copyright 2022 Inc. All Rights Reserved.
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

package licenses

import (
	"strings"

	"golang.org/x/tools/go/packages"
)

// Module provides module information for a package.
type Module struct {
	// Differences from packages.Module:
	// * Replace field is removed, it's only an implementation detail in this package.
	//   If a module is replaced, we'll directly return the replaced module.
	// * Version field +incompatible suffix is trimmed.
	// * Main, ModuleError, Time, Indirect, GoMod, GoVersion fields are removed, because they are not used.
	Path    string // module path
	Version string // module version
	Dir     string // directory holding files for this module, if any
}

func newModule(mod *packages.Module) *Module {
	// Example of a module with replace directive: 	k8s.io/kubernetes => k8s.io/kubernetes v1.11.1
	// {
	//         "Path": "k8s.io/kubernetes",
	//         "Version": "v0.17.9",
	//         "Replace": {
	//                 "Path": "k8s.io/kubernetes",
	//                 "Version": "v1.11.1",
	//                 "Time": "2018-07-17T04:20:29Z",
	//                 "Dir": "/home/gongyuan_kubeflow_org/go/pkg/mod/k8s.io/kubernetes@v1.11.1",
	//                 "GoMod": "/home/gongyuan_kubeflow_org/go/pkg/mod/cache/download/k8s.io/kubernetes/@v/v1.11.1.mod"
	//         },
	//         "Dir": "/home/gongyuan_kubeflow_org/go/pkg/mod/k8s.io/kubernetes@v1.11.1",
	//         "GoMod": "/home/gongyuan_kubeflow_org/go/pkg/mod/cache/download/k8s.io/kubernetes/@v/v1.11.1.mod"
	// }
	// handle replace directives
	// Note, we specifically want to replace version field.
	// Haven't confirmed, but we may also need to override the
	// entire struct when using replace directive with local folders.
	tmp := *mod
	if tmp.Replace != nil {
		tmp = *tmp.Replace
	}

	// The +incompatible suffix does not affect module version.
	// ref: https://golang.org/ref/mod#incompatible-versions
	tmp.Version = strings.TrimSuffix(tmp.Version, "+incompatible")
	return &Module{
		Path:    tmp.Path,
		Version: tmp.Version,
		Dir:     tmp.Dir,
	}
}
