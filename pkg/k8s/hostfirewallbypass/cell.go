// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hostfirewallbypass

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

// Provides a host firewall bypass for k8s Clientset
// when accessing Kubernetes objects.
var Cell = cell.Module(
	"k8s-host-firewall-bypaass",
	"Kubernetes host firewall bypass",

	cell.Config(Params{
		EnableK8sHostFirewallBypass: false,
	}),
	cell.Provide(NewK8sHostFirewallBypass),
)

type Params struct {
	EnableK8sHostFirewallBypass bool
}

func (p Params) Flags(flags *pflag.FlagSet) {
	enable := "enable-k8s-host-firewall-bypass"
	flags.Bool(enable, p.EnableK8sHostFirewallBypass, "Enable bypassing host firewall for Kubernetes API server access.")
	flags.MarkHidden(enable)
}
