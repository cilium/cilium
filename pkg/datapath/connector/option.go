// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package connector

// Available option for DaemonConfig.Ipvlan.OperationMode
const (
	// OperationModeL3S will respect iptables rules e.g. set up for masquerading
	OperationModeL3S = "L3S"

	// OperationModeL3 will bypass iptables rules on the host
	OperationModeL3 = "L3"
)
