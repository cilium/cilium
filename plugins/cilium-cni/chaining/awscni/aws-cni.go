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
	awsCNIRes := awsCNIResult(*prevRes)

	sgppHostIface, ok := awsCNIRes.getSGPPHostIface()
	if !ok || !pluginCtx.NetConf.ProxyRouting {
		return f.GenericVethChainer.Add(ctx, pluginCtx, cli)
	}
	pluginCtx.Logger.Debug("found security group attached Pod")

	sgppVLANID, ok := awsCNIRes.getSGPPVLANID()
	if !ok {
		err = fmt.Errorf("failed to retrieve SGP Pod VLAN ID")
		return
	}
	sgppAddr, ok := awsCNIRes.getSGPPAddr()
	if !ok {
		err = fmt.Errorf("failed to retrieve SGP Pod address")
		return
	}
	err = installSGPPProxyRules(sgppVLANID, sgppAddr)
	if err != nil {
		err = fmt.Errorf("failed to install SGP Pod proxy rules: %w", err)
		return
	}

	err = pluginCtx.Sysctl.Disable([]string{
		"net", "ipv4", "conf", sgppHostIface, "rp_filter"})
	if err != nil {
		err = fmt.Errorf("failed to configure SGP Pod VLAN interface: %w", err)
		return
	}
	err = pluginCtx.Sysctl.Disable([]string{
		"net", "ipv4", "conf", buildSGPPVLANIfaceName(sgppVLANID), "rp_filter"})
	if err != nil {
		err = fmt.Errorf("failed to configure SGP Pod host interface: %w", err)
		return
	}
	return f.GenericVethChainer.Add(ctx, pluginCtx, cli)
}
