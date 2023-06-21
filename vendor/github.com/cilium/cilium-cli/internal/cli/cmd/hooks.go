// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/sysdump"
)

// Hooks to extend the default cilium-cli command with additional functionality.
type Hooks interface {
	ConnectivityTestHooks
	SysdumpHooks
}

// ConnectivityTestHooks to extend cilium-cli with additional connectivity tests and related flags.
type ConnectivityTestHooks interface {
	AddConnectivityTestFlags(flags *pflag.FlagSet)
	AddConnectivityTests(ct *check.ConnectivityTest) error
}

// SysdumpHooks to extend cilium-cli with additional sysdump tasks and related flags.
type SysdumpHooks interface {
	AddSysdumpFlags(flags *pflag.FlagSet)
	AddSysdumpTasks(*sysdump.Collector) error
}
