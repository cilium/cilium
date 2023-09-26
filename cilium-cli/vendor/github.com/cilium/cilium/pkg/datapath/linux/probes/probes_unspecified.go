// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package probes

// Dummy values on non-linux platform
const (
	NTF_EXT_LEARNED = iota
	NTF_EXT_MANAGED
)
