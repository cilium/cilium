// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium-cli/connectivity"
	"github.com/cilium/cilium-cli/sysdump"
)

// Hooks to extend the default cilium-cli command with additional functionality.
type Hooks interface {
	ConnectivityTestHooks
	SysdumpHooks
}

// ConnectivityTestHooks to extend cilium-cli with additional connectivity tests and related flags.
type ConnectivityTestHooks interface {
	connectivity.Hooks
	// AddConnectivityTestFlags is an hook to register additional connectivity test flags.
	AddConnectivityTestFlags(flags *pflag.FlagSet)
}

// SysdumpHooks to extend cilium-cli with additional sysdump tasks and related flags.
type SysdumpHooks interface {
	AddSysdumpFlags(flags *pflag.FlagSet)
	AddSysdumpTasks(*sysdump.Collector) error
}
