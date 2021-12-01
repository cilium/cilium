// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package common

const (
	// Miscellaneous dedicated constants

	// CHeaderFileName is the name of the C header file for BPF programs for a
	// particular endpoint.
	CHeaderFileName = "ep_config.h"

	// PossibleCPUSysfsPath is used to retrieve the number of CPUs for per-CPU maps.
	PossibleCPUSysfsPath = "/sys/devices/system/cpu/possible"
)
