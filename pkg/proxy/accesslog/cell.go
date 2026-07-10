// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package accesslog

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

// Cell provides the Proxy Access logging infrastructure that allows for sending
// L7 proxy access flow logs.
var Cell = cell.Module(
	"proxy-logger",
	"Proxy Logger provides support for L7 proxy access flow logging",

	cell.Provide(NewProxyAccessLogger),
	cell.ProvidePrivate(newMonitorAgentLogRecordNotifier),
	cell.Config(ProxyAccessLoggerConfig{}),
)

type ProxyAccessLoggerConfig struct {
	AgentLabels []string
}

func (r ProxyAccessLoggerConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("agent-labels", []string{}, "Additional labels to identify this agent in monitor events")
}
