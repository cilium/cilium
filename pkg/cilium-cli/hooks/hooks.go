// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hooks

import (
	"context"

	"github.com/cilium/cilium-cli/sysdump"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/cilium-cli/connectivity"
	"github.com/cilium/cilium/pkg/cilium-cli/connectivity/check"
)

// ConnectivityTestHooks to extend cilium-cli with additional connectivity tests and related flags.
type ConnectivityTestHooks interface {
	connectivity.Hooks
	// AddConnectivityTestFlags is an hook to register additional connectivity test flags.
	AddConnectivityTestFlags(flags *pflag.FlagSet)
}

// Hooks to extend the default cilium-cli command with additional functionality.
type Hooks interface {
	ConnectivityTestHooks
	SysdumpHooks
}

// SysdumpHooks to extend cilium-cli with additional sysdump tasks and related flags.
type SysdumpHooks interface {
	AddSysdumpFlags(flags *pflag.FlagSet)
	AddSysdumpTasks(*sysdump.Collector) error
}

type NopHooks struct{}

var _ Hooks = &NopHooks{}

func (*NopHooks) AddSysdumpFlags(*pflag.FlagSet)                                  {}
func (*NopHooks) AddSysdumpTasks(*sysdump.Collector) error                        { return nil }
func (*NopHooks) AddConnectivityTestFlags(*pflag.FlagSet)                         {}
func (*NopHooks) AddConnectivityTests(*check.ConnectivityTest) error              { return nil }
func (*NopHooks) DetectFeatures(context.Context, *check.ConnectivityTest) error   { return nil }
func (*NopHooks) SetupAndValidate(context.Context, *check.ConnectivityTest) error { return nil }
