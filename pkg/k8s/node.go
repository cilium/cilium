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

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
)

// ParseNode parses a kubernetes node to a cilium node
func ParseNode(k8sNode *v1.Node) *node.Node {
	addrs := []node.Address{}
	for _, addr := range k8sNode.Status.Addresses {
		// We only care about this address types,
		// we ignore all other types.
		switch addr.Type {
		case v1.NodeInternalIP, v1.NodeExternalIP:
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
	// Spec.PodCIDR takes precedence since it's
	// the CIDR assigned by k8s controller manager
	// In case it's invalid or empty then we fall back to our annotations.
	if node.IPv4AllocCIDR == nil {
		if ipv4CIDR, ok := k8sNode.Annotations[Annotationv4CIDRName]; !ok {
			log.Debugf("k8s: Empty IPv4 CIDR annotation in node")
		} else {
			_, cidr, err := net.ParseCIDR(ipv4CIDR)
			if err != nil {
				log.Errorf("k8s: BUG, invalid IPv4 annotation CIDR %q in node %q: %s",
					ipv4CIDR, k8sNode.Name, err)
			} else {
				node.IPv4AllocCIDR = cidr
			}
		}
	}

	if node.IPv6AllocCIDR == nil {
		if ipv6CIDR, ok := k8sNode.Annotations[Annotationv6CIDRName]; !ok {
			log.Debugf("k8s: Empty IPv6 CIDR annotation in node")
		} else {
			_, cidr, err := net.ParseCIDR(ipv6CIDR)
			if err != nil {
				log.Errorf("k8s: BUG, invalid IPv6 annotation CIDR %q in node %q: %s",
					ipv6CIDR, k8sNode.Name, err)
			} else {
				node.IPv6AllocCIDR = cidr
			}
		}
	}

	return node
}

// GetNode returns the kubernetes nodeName's node information from the
// kubernetes api server
func GetNode(c kubernetes.Interface, nodeName string) (*v1.Node, error) {
	// Try to retrieve node's cidr and addresses from k8s's configuration
	return c.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
}
