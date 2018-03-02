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

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/tunnel"

	"github.com/sirupsen/logrus"
)

type tunnelConfiguration struct {
	prefix    *net.IPNet
	ip        net.IP
	encapType string
}

type datapathConfiguration struct {
	tunnelDestinations map[string]tunnelConfiguration
	routes             []route
}

func (dc *datapathConfiguration) findRoute(rc route) *route {
	for _, r := range dc.routes {
		if r.Equal(rc) {
			return &r
		}
	}

	return nil
}

func newDatapathConfiguration() datapathConfiguration {
	return datapathConfiguration{
		tunnelDestinations: map[string]tunnelConfiguration{},
	}
}

// nodeState is the representation of the desired and realized node state
type nodeState struct {
	node Node

	// desired is the latest node information received from the node
	// discovery mechanism
	desired datapathConfiguration

	// realized is the latest state implemented in the datapath
	realized datapathConfiguration
}

func newNodeState() *nodeState {
	return &nodeState{
		desired:  newDatapathConfiguration(),
		realized: newDatapathConfiguration(),
	}
}

func (ns *nodeState) synchronizeToDatapath() {
	// Remove all tunnel destination that are no longer desired
	for ip, t := range ns.realized.tunnelDestinations {
		if _, ok := ns.desired.tunnelDestinations[ip]; !ok {
			if err := tunnel.DeleteTunnelEndpoint(t.prefix.IP); err != nil {
				log.WithError(err).WithField(logfields.IPAddr, t.prefix.IP).
					Warning("Unable to delete tunnel map entry")
			} else {
				delete(ns.realized.tunnelDestinations, ip)
			}
		}
	}

	for remoteNodeIP, t := range ns.desired.tunnelDestinations {
		if err := tunnel.SetTunnelEndpoint(t.prefix.IP, t.ip); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr: t.prefix,
				"nodeIP":         t.ip.String(),
			}).Warning("Unable to update tunnel map entry")
		} else {
			ns.realized.tunnelDestinations[remoteNodeIP] = t
		}
	}

	for _, rt := range ns.realized.routes {
		if ns.desired.findRoute(rt) == nil {
			rt.delete()
		}
	}

	for _, rt := range ns.desired.routes {
		if ns.realized.findRoute(rt) == nil {
			rt.add()
		}
	}
}

// getDatapathConfiguration generates and returns the datapath representation
// required to establish connectivity to specified node
func (n *Node) getDatapathConfiguration() datapathConfiguration {
	cfg := newDatapathConfiguration()

	if n.EncapsulationEnabled() {
		// GH-4084: For now, the datapath is only capable of reaching
		// other nodes using encapsulation protocols that match the
		// local configuration.
		localMode := GetLocalNode().Routing.Encapsulation
		if n.Routing.Encapsulation != localMode {
			n.getLogger().Warningf("Remote node is requesting to be reached via %s, local node is using %s",
				n.Routing.Encapsulation, localMode)
		} else {
			if n.IPv4AllocCIDR != nil {
				cfg.tunnelDestinations[n.GetNodeIP(false).String()] = tunnelConfiguration{
					prefix:    n.IPv4AllocCIDR,
					encapType: n.Routing.Encapsulation,
				}
			}

			if n.IPv6AllocCIDR != nil {
				cfg.tunnelDestinations[n.GetNodeIP(true).String()] = tunnelConfiguration{
					prefix:    n.IPv6AllocCIDR,
					encapType: n.Routing.Encapsulation,
				}
			}
		}
	}

	cfg.routes = []route{}

	if n.IPv6AllocCIDR != nil {
		cfg.routes = append(cfg.routes, n.generateRoute(n.IPv6AllocCIDR))
	}

	if n.IPv4AllocCIDR != nil {
		cfg.routes = append(cfg.routes, n.generateRoute(n.IPv4AllocCIDR))
	}

	return cfg
}
