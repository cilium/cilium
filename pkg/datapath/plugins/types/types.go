// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"

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
	// DeepEqual returns true if this plugin is equivalent to o.
	DeepEqual(o Plugin) bool
}

// Plugins is a mapping between plugin names and Plugins.
type Plugins map[string]Plugin

// DeepEqual returns true if all plugins are equal to those in o.
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

// Registry contains all registered datapath plugins.
type Registry interface {
	// Register registers a plugin and sets up a client to talk to it.
	Register(dpp *api_v2alpha1.CiliumDatapathPlugin)
	// Unregister unregisters a plugin and shuts down its client.
	Unregister(dpp *api_v2alpha1.CiliumDatapathPlugin)
	// Plugins returns a snapshot of the current state of the registry.
	Plugins() Plugins
	// Sync blocks until the registry is initialized or until ctx is done.
	Sync(ctx context.Context) error
}
