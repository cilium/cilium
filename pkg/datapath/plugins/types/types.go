// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/api/v1/datapathplugins"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// A Plugin represents a registered datapath plugin and its client.
type Plugin interface {
	datapathplugins.DatapathPluginClient
	// Name returns the name of this datapath plugin.
	Name() string
	// AttachmentPolicy returns the attachment policy for this plugin.
	AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
}

// Plugins is a mapping between plugin names and Plugins.
type Plugins map[string]Plugin

// Registry contains all registered datapath plugins.
type Registry interface {
	// Register registers a plugin and sets up a client to talk to it.
	Register(dpp *api_v2alpha1.CiliumDatapathPlugin)
	// Unregister unregisters a plugin and shuts down its client.
	Unregister(dpp *api_v2alpha1.CiliumDatapathPlugin)
	// Plugins returns a snapshot of the current state of the registry.
	Plugins() Plugins
}
