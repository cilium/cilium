package types

import (
	"github.com/cilium/cilium/api/v1/datapathplugins"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type Plugin interface {
	datapathplugins.DatapathPluginClient
	Name() string
	AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
}

type Plugins map[string]Plugin

type Registry interface {
	IsEnabled() bool
	Register(dpp *api_v2alpha1.CiliumDatapathPlugin)
	Unregister(dpp *api_v2alpha1.CiliumDatapathPlugin)
	Plugins() Plugins
}
