// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package awscni

import (
	"context"
	"fmt"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/pkg/client"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	genericveth "github.com/cilium/cilium/plugins/cilium-cni/chaining/generic-veth"
)

func init() {
	chainingapi.Register("aws-cni", &AWSCNIChainer{})
}

type AWSCNIChainer struct {
	genericveth.GenericVethChainer
}

func (f *AWSCNIChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	prevRes, err := cniTypesVer.NewResultFromResult(pluginCtx.NetConf.PrevResult)
	if err != nil {
		err = fmt.Errorf("unable to understand network config: %w", err)
		return
	}
	if !isSGPPodAttachment(prevRes) || !pluginCtx.NetConf.ProxyRouting {
		return f.GenericVethChainer.Add(ctx, pluginCtx, cli)
	}
	pluginCtx.Logger.Debug("found security group attached Pod")

	// If this is an attachment for a security group attached Pod (SGP Pod),
	// we need to do some additional setup to ensure traffic is routed
	// correctly to and from an L7 ingress proxy when L7 policies are applied.
	sgpPodVLANID := getSGPPodVLANID(prevRes)
	sgpPodAddr := getSGPPodAddr(prevRes)
	if err = installSGPPodProxyRules(sgpPodVLANID, sgpPodAddr); err != nil {
		err = fmt.Errorf("failed to install SGP Pod proxy rules: %w", err)
		return
	}
	sgpPodHostIface := getHostIface(prevRes)
	err = pluginCtx.Sysctl.Disable([]string{
		"net", "ipv4", "conf", sgpPodHostIface, "rp_filter"})
	if err != nil {
		err = fmt.Errorf("failed to configure SGP Pod VLAN interface: %w", err)
		return
	}
	err = pluginCtx.Sysctl.Disable([]string{
		"net", "ipv4", "conf", buildSGPPodVLANIfaceName(sgpPodVLANID), "rp_filter"})
	if err != nil {
		err = fmt.Errorf("failed to configure SGP Pod host interface: %w", err)
		return
	}
	return f.GenericVethChainer.Add(ctx, pluginCtx, cli)
}
