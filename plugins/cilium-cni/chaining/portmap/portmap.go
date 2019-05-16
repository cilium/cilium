// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
