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
	"github.com/cilium/cilium/pkg/option"

	"k8s.io/api/core/v1"
	"time"
)

var localNode Node

// GetLocalNode returns the identity and node spec for the local node
func GetLocalNode() *Node {
	return &localNode
}

// ConfigureLocalNode configures the local node. This is called on agent
// startup to configure the local node based on the configuration options
// passed to the agent
func ConfigureLocalNode() error {
	localNode = Node{
		Name:    nodeName,
		Cluster: option.Config.ClusterName,
		cluster: clusterConf,
		IPAddresses: []Address{
			{
				AddressType: v1.NodeInternalIP,
				IP:          GetExternalIPv4(),
			},
		},
		IPv4AllocCIDR: GetIPv4AllocRange(),
		IPv6AllocCIDR: GetIPv6AllocRange(),
		IPv4HealthIP:  GetIPv4HealthIP(),
		IPv6HealthIP:  GetIPv6HealthIP(),
		ClusterID:     option.Config.ClusterID,
	}

	UpdateNode(&localNode, TunnelRoute, nil)

	nodeRegistered := make(chan struct{})
	go func() {
		if err := registerNode(); err != nil {
			log.WithError(err).Fatal("Unable to initialize local node")
		}
		close(nodeRegistered)
	}()
	go func() {
		select {
		case <-nodeRegistered:
		case <-time.NewTimer(3 * time.Minute).C:
			log.Fatalf("Unable to initialize local node due timeout")
		}
	}()
	return nil
}
