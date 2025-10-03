// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !race

// This file is compiled only when race detection is NOT enabled.

package gc

var skipGlobalStateRestoration = false
