// Copyright 2016-2018 Authors of Cilium
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

package node

import (
	"net"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

const (
	defaultClusterName = "default"
)

type clusterConfiguation struct {
	lock.RWMutex

	name             string
	nodes            map[Identity]*nodeState
	usePerNodeRoutes bool
	auxPrefixes      []*net.IPNet
	controllers      controller.Manager
}

var clusterConf = newClusterConfiguration()

func newClusterConfiguration() clusterConfiguation {
	return clusterConfiguation{
		name:        defaultClusterName,
		nodes:       map[Identity]*nodeState{},
		auxPrefixes: []*net.IPNet{},
	}
}

func (cc *clusterConfiguation) addAuxPrefix(prefix *net.IPNet) {
	cc.Lock()
	cc.auxPrefixes = append(cc.auxPrefixes, prefix)
	cc.Unlock()
}

// GetNode returns the node with the given identity, if exists, from the nodes
// map.
func GetNode(ni Identity) *Node {
	clusterConf.RLock()
	defer clusterConf.RUnlock()

	if state, ok := clusterConf.nodes[ni]; ok {
		return &state.node
	}

	return nil
}

// InstallHostRoutes installs all required routes to make the following IP
// spaces available from the local host:
//  - node CIDR of local and remote nodes
//  - service CIDR range
//
// This may only be called after the cilium_host interface has been initialized
// for the first time
func InstallHostRoutes() {
	clusterConf.controllers.UpdateController("sync-cluster-routing",
		controller.ControllerParams{
			DoFunc: func() error {
				return clusterConf.syncClusterRouting()
			},
			RunInterval: time.Minute,
		},
	)
}

// AddAuxPrefix adds additional prefixes for which routes should be installed
// that point to the Cilium network. This function does not directly install
// the route but schedules it for addition by InstallHostRoutes
func AddAuxPrefix(prefix *net.IPNet) {
	clusterConf.addAuxPrefix(prefix)
}

// EnablePerNodeRoutes enables use of per node routes. This function must be called
// at init time before any routes are installed.
func EnablePerNodeRoutes() {
	clusterConf.Lock()
	clusterConf.usePerNodeRoutes = true
	clusterConf.Unlock()
}

// GetNodes returns a copy of all of the nodes as a map from Identity to Node.
func GetNodes() map[Identity]Node {
	clusterConf.RLock()
	defer clusterConf.RUnlock()

	nodes := make(map[Identity]Node)
	for id, state := range clusterConf.nodes {
		nodes[id] = state.node
	}

	return nodes
}
