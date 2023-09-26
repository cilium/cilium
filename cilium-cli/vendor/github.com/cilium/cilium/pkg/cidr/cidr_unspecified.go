// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cidr

// Dummy values on non-linux platform
const (
	FAMILY_V4 = iota
	FAMILY_V6
)
