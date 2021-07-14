// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

package portmap

import (
	"context"

	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
)

type portmapChainer struct{}

func (p *portmapChainer) ImplementsAdd() bool {
	return false
}

func (p *portmapChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext) (res *cniTypesVer.Result, err error) {
	return nil, nil
}

func (p *portmapChainer) ImplementsDelete() bool {
	return false
}

func (p *portmapChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext) (err error) {
	return nil
}

func init() {
	chainingapi.Register("portmap", &portmapChainer{})
}
