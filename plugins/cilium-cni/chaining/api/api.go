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

package api

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/plugins/cilium-cni/types"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
	"github.com/sirupsen/logrus"
)

var (
	chainingPlugins = map[string]ChainingPlugin{}
	mutex           lock.RWMutex
)

// PluginContext is the context given to chaining plugins
type PluginContext struct {
	Logger  *logrus.Entry
	Args    *skel.CmdArgs
	CniArgs types.ArgsSpec
	NetConf *types.NetConf
	Client  *client.Client
}

// ChainingPlugin is the interface each chaining plugin must implement
type ChainingPlugin interface {
	// Add is called on CNI ADD. It is given the plugin context from the
	// previous plugin. It must return a CNI result or an error.
	Add(ctx context.Context, pluginContext PluginContext) (res *cniTypesVer.Result, err error)

	// ImplementsAdd returns true if the chaining plugin implements its own
	// add logic
	ImplementsAdd() bool

	// Delete is called on CNI DELETE. It is given the plugin context from
	// the previous plugin.
	Delete(ctx context.Context, pluginContext PluginContext) (err error)

	// ImplementsDelete returns true if the chaining plugin implements its
	// own delete logic
	ImplementsDelete() bool
}

// Register is called by chaining plugins to register themselves. After
// Register(), the plugin can be found with Lookup().
func Register(name string, p ChainingPlugin) error {
	mutex.Lock()
	defer mutex.Unlock()

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
