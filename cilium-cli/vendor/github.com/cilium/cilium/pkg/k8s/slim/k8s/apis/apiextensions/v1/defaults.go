// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2019 The Kubernetes Authors.

package v1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}
