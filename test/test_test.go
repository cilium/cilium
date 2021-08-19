// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

//go:build integration_tests
// +build integration_tests

package ciliumTest

import (
	// test sources
	_ "github.com/cilium/cilium/test/k8sT"
	_ "github.com/cilium/cilium/test/runtime"
)
