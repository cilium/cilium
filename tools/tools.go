// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

// +build tools

package tools

import (
	_ "github.com/cilium/customvet"
	_ "github.com/cilium/deepequal-gen"
	_ "k8s.io/code-generator"
	_ "k8s.io/code-generator/cmd/client-gen"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"

	// Used for protobuf generation of pkg/k8s/types/slim/k8s
	_ "github.com/gogo/protobuf/gogoproto"
	_ "golang.org/x/tools/cmd/goimports"
	_ "k8s.io/code-generator/cmd/go-to-protobuf"
	_ "k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo"
)
