// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package portmap

import (
	"context"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/pkg/client"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
)

type portmapChainer struct{}

func (p *portmapChainer) ImplementsAdd() bool {
	return false
}

func (p *portmapChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	return nil, nil
}

func (p *portmapChainer) ImplementsDelete() bool {
	return false
}

func (p *portmapChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *lib.DeletionFallbackClient) (err error) {
	return nil
}

func (p *portmapChainer) Check(ctx context.Context, pluginContext chainingapi.PluginContext, cli *client.Client) error {
	return nil
}

func init() {
	chainingapi.Register("portmap", &portmapChainer{})
}
