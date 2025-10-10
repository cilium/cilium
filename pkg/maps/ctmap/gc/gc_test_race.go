// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build race

// This file is compiled only when race detection is enabled.
// It provides alternate behavior for race-sensitive operations.

package gc

var skipGlobalStateRestoration = true
