// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

type ConnectorUserConfig struct {
	// EnableTunedBufferMargins enables logic that aims to tune the buffer
	// margins of workload facing network devices.
	EnableTunedBufferMargins bool
}

func (def ConnectorUserConfig) IsTunedBufferMarginsEnabled() bool {
	return def.EnableTunedBufferMargins
}
