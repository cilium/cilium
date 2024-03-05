// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/internal/cli/cmd"
	"github.com/cilium/cilium-cli/sysdump"
)

// NewDefaultCiliumCommand returns a new "cilium" cli cobra command without any additional hooks.
func NewDefaultCiliumCommand() *cobra.Command {
	return NewCiliumCommand(&NopHooks{})
}

// NewCiliumCommand returns a new "cilium" cli cobra command registering all the additional input hooks.
func NewCiliumCommand(hooks Hooks) *cobra.Command {
	return cmd.NewCiliumCommand(hooks)
}

type (
	Hooks                 = cmd.Hooks
	ConnectivityTestHooks = cmd.ConnectivityTestHooks
	SysdumpHooks          = sysdump.Hooks
)

type NopHooks struct{}

var _ Hooks = &NopHooks{}

func (*NopHooks) AddSysdumpFlags(*pflag.FlagSet)                                  {}
func (*NopHooks) AddSysdumpTasks(*sysdump.Collector) error                        { return nil }
func (*NopHooks) AddConnectivityTestFlags(*pflag.FlagSet)                         {}
func (*NopHooks) AddConnectivityTests(*check.ConnectivityTest) error              { return nil }
func (*NopHooks) DetectFeatures(context.Context, *check.ConnectivityTest) error   { return nil }
func (*NopHooks) SetupAndValidate(context.Context, *check.ConnectivityTest) error { return nil }
