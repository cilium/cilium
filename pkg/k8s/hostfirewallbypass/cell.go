// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hostfirewallbypass

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

// Provides a host firewall bypass for k8s Clientset
// when accessing Kubernetes objects.
var Cell = cell.Module(
	"k8s-host-firewall-bypass",
	"Kubernetes host firewall bypass",

	cell.Config(config{
		EnableK8sHostFirewallBypass: true,
	}),
	cell.Provide(NewK8sHostFirewallBypass),
)

type Params struct {
	cell.In

	DaemonConfig *option.DaemonConfig `optional:"true"`
	LocalConfig  config
}

type config struct {
	EnableK8sHostFirewallBypass bool
}

func (p config) Flags(flags *pflag.FlagSet) {
	enable := "enable-k8s-host-firewall-bypass"
	flags.Bool(enable, p.EnableK8sHostFirewallBypass, "Enable bypassing host firewall for Kubernetes API server access.")
	flags.MarkHidden(enable)
}
