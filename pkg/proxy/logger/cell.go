// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

// Cell provides the Proxy Access logging infrastructure that allows for sending
// L7 proxy access flow logs.
var Cell = cell.Module(
	"proxy-logger",
	"Proxy Logger provides support for L7 proxy access flow logging",

	cell.Provide(newProcyAccessLogger),
	cell.ProvidePrivate(NewMonitorAgentLogRecordNotifier),
	cell.Config(proxyAccessLoggerConfig{}),
)

type proxyAccessLoggerConfig struct {
	// AgentLabels []string
}

func (r proxyAccessLoggerConfig) Flags(flags *pflag.FlagSet) {
	// flags.StringSlice("agent-labels", []string{}, "AgentLabels are additional labels to identify this agent")
}
