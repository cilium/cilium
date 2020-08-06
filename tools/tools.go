// Copyright 2019-2020 Authors of Cilium
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

// +build tools

package tools

import (
	_ "github.com/cilium/deepequal-gen"
	_ "github.com/go-bindata/go-bindata/v3"
	_ "github.com/go-bindata/go-bindata/v3/go-bindata"
	_ "k8s.io/code-generator"
	_ "k8s.io/code-generator/cmd/client-gen"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"

	// Used for protobuf generation of pkg/k8s/types/slim/k8s
	_ "github.com/gogo/protobuf/gogoproto"
	_ "golang.org/x/tools/cmd/goimports"
	_ "k8s.io/code-generator/cmd/go-to-protobuf"
	_ "k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo"
)
