// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build integration_tests

package ciliumTest

import (
	// test sources
	_ "github.com/cilium/cilium/test/k8s"
	_ "github.com/cilium/cilium/test/runtime"
)
