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

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ParseNode parses a kubernetes node to a cilium node
func ParseNode(k8sNode *v1.Node, source node.Source) *node.Node {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName:  k8sNode.Name,
		logfields.K8sNodeID: k8sNode.UID,
	})
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
			scopedLog.WithFields(logrus.Fields{
				logfields.IPAddr: addr.Address,
				"type":           addr.Type,
			}).Warn("Ignoring invalid node IP")
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
		Source:      source,
	}

	if len(k8sNode.Spec.PodCIDR) != 0 {
		if _, cidr, err := net.ParseCIDR(k8sNode.Spec.PodCIDR); err != nil {
			scopedLog.WithError(err).WithField(logfields.V4Prefix, k8sNode.Spec.PodCIDR).Warn("Invalid PodCIDR value for node")
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
		if ipv4CIDR, ok := k8sNode.Annotations[annotation.V4CIDRName]; !ok {
			scopedLog.Debug("Empty IPv4 CIDR annotation in node")
		} else {
			_, cidr, err := net.ParseCIDR(ipv4CIDR)
			if err != nil {
				scopedLog.WithError(err).WithField(logfields.V4Prefix, ipv4CIDR).Error("BUG, invalid IPv4 annotation CIDR in node")
			} else {
				node.IPv4AllocCIDR = cidr
			}
		}
	}

	if node.IPv6AllocCIDR == nil {
		if ipv6CIDR, ok := k8sNode.Annotations[annotation.V6CIDRName]; !ok {
			scopedLog.Debug("Empty IPv6 CIDR annotation in node")
		} else {
			_, cidr, err := net.ParseCIDR(ipv6CIDR)
			if err != nil {
				scopedLog.WithError(err).WithField(logfields.V6Prefix, ipv6CIDR).Error("BUG, invalid IPv6 annotation CIDR in node")
			} else {
				node.IPv6AllocCIDR = cidr
			}
		}
	}

	if node.IPv4HealthIP == nil {
		if healthIP, ok := k8sNode.Annotations[annotation.V4HealthName]; !ok {
			scopedLog.Debug("Empty IPv4 health endpoint annotation in node")
		} else if ip := net.ParseIP(healthIP); ip == nil {
			scopedLog.WithField(logfields.V4HealthIP, healthIP).Error("BUG, invalid IPv4 health endpoint annotation in node")
		} else {
			node.IPv4HealthIP = ip
		}
	}

	if node.IPv6HealthIP == nil {
		if healthIP, ok := k8sNode.Annotations[annotation.V6HealthName]; !ok {
			scopedLog.Debug("Empty IPv6 health endpoint annotation in node")
		} else if ip := net.ParseIP(healthIP); ip == nil {
			scopedLog.WithField(logfields.V6HealthIP, healthIP).Error("BUG, invalid IPv6 health endpoint annotation in node")
		} else {
			node.IPv6HealthIP = ip
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
