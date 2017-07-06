// Copyright 2016-2017 Authors of Cilium
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

package k8s

import (
	"net"

	"github.com/cilium/cilium/pkg/node"

	log "github.com/Sirupsen/logrus"
	"k8s.io/client-go/pkg/api/v1"
)

// ParseNode parses a kubernetes node to a cilium node
func ParseNode(k8sNode *v1.Node) *node.Node {
	addrs := []node.Address{}
	for _, addr := range k8sNode.Status.Addresses {
		// We only care about this address types,
		// we ignore all other types.
		switch addr.Type {
		case v1.NodeLegacyHostIP, v1.NodeInternalIP, v1.NodeExternalIP:
		default:
			continue
		}
		ip := net.ParseIP(addr.Address)
		if ip == nil {
			log.Debugf("k8s: Ignoring invalid node IP %s of type %s", addr.Address, addr.Type)
			continue
		}
		na := node.Address{
			AddressType: addr.Type,
			IP:          ip,
		}
		addrs = append(addrs, na)
	}

	node := &node.Node{
		Name:        k8sNode.Name,
		IPAddresses: addrs,
	}

	if len(k8sNode.Spec.PodCIDR) != 0 {
		if _, cidr, err := net.ParseCIDR(k8sNode.Spec.PodCIDR); err != nil {
			log.Warningf("k8s: Invalid PodCIDR value '%s' for node %s: %s", k8sNode.Spec.PodCIDR, err)
		} else {
			if cidr.IP.To4() != nil {
				node.IPv4AllocCIDR = cidr
			} else {
				node.IPv6AllocCIDR = cidr
			}
		}
	}

	return node
}
