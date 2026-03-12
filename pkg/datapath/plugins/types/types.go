package types

import (
	"context"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type Plugin interface {
	datapathplugins.DatapathPluginClient
	Name() string
	AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
	DeepEqual(o Plugin) bool
}

type Plugins map[string]Plugin

func (p *Plugins) DeepEqual(o *Plugins) bool {
	if p == nil {
		return o == nil
	} else if o == nil {
		return false
	}

	if len(*p) != len(*o) {
		return false
	}

	for name, plugin := range *p {
		if _, ok := (*o)[name]; !ok {
			return false
		}
		if !plugin.DeepEqual((*o)[name]) {
			return false
		}
	}

	return true
}

type Registry interface {
	IsEnabled() bool
	Register(dpp *api_v2alpha1.CiliumDatapathPlugin)
	Unregister(dpp *api_v2alpha1.CiliumDatapathPlugin)
	Plugins() Plugins
	Sync(ctx context.Context) error
}
