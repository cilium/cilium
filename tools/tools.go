// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build tools

package tools

import (
	_ "github.com/cilium/customvet"
	_ "github.com/cilium/deepequal-gen"
	_ "github.com/gogo/protobuf/gogoproto" // Used for protobuf generation of pkg/k8s/types/slim/k8s
	_ "golang.org/x/tools/cmd/goimports"
	_ "k8s.io/code-generator"
	_ "k8s.io/code-generator/cmd/client-gen"
	_ "k8s.io/code-generator/cmd/go-to-protobuf"
	_ "k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
