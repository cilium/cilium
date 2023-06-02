// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

var (
	chainingPlugins = map[string]ChainingPlugin{}
	mutex           lock.RWMutex
)

const (
	// DefaultConfigName is the name used by default in the standard CNI
	// configuration
	DefaultConfigName = "cilium"
)

// PluginContext is the context given to chaining plugins
type PluginContext struct {
	Logger  *logrus.Entry
	Args    *skel.CmdArgs
	CniArgs types.ArgsSpec
	NetConf *types.NetConf
	//Client  *client.Client
}

// ChainingPlugin is the interface each chaining plugin must implement
type ChainingPlugin interface {
	// Add is called on CNI ADD. It is given the plugin context from the
	// previous plugin. It must return a CNI result or an error.
	Add(ctx context.Context, pluginContext PluginContext, client *client.Client) (res *cniTypesVer.Result, err error)

	// Delete is called on CNI DELETE. It is given the plugin context from
	// the previous plugin.
	Delete(ctx context.Context, pluginContext PluginContext, delClient *lib.DeletionFallbackClient) (err error)

	// Check is called on CNI CHECK. The plugin should verify (to the best of its
	// ability) that everything is reasonably configured, else return error.
	Check(ctx context.Context, pluginContext PluginContext, client *client.Client) error
}

// Register is called by chaining plugins to register themselves. After
// Register(), the plugin can be found with Lookup().
func Register(name string, p ChainingPlugin) error {
	mutex.Lock()
	defer mutex.Unlock()

	if name == DefaultConfigName {
		return fmt.Errorf("invalid chain name. '%s' is reserved", DefaultConfigName)
	}

	if _, ok := chainingPlugins[name]; ok {
		return fmt.Errorf("chaining plugin with name %s already exists", name)
	}

	chainingPlugins[name] = p

	return nil
}

// Lookup searches for a chaining plugin with a given name and returns it
func Lookup(name string) ChainingPlugin {
	mutex.RLock()
	defer mutex.RUnlock()

	return chainingPlugins[name]
}
