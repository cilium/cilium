// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"
)

const (
	EnableTunedBufferMarginsFlag = "enable-tuned-buffer-margins"
)

type ConnectorUserConfig struct {
	// EnableTunedBufferMargins enables logic that aims to tune the buffer
	// margins of workload facing network devices.
	EnableTunedBufferMargins bool
}

func (def ConnectorUserConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableTunedBufferMarginsFlag, def.EnableTunedBufferMargins,
		"Enable tuned buffer margins on pod network interfaces")
}

func (def ConnectorUserConfig) IsTunedBufferMarginsEnabled() bool {
	return def.EnableTunedBufferMargins
}

type ConnectorConfig interface {
	IsTunedBufferMarginsEnabled() bool
}
