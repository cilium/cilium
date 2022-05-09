// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
)

// ParseNodeAddressType converts a Kubernetes NodeAddressType to a Cilium
// NodeAddressType. If the Kubernetes NodeAddressType does not have a
// corresponding Cilium AddressType, returns an error.
func ParseNodeAddressType(k8sAddress slim_corev1.NodeAddressType) (addressing.AddressType, error) {

	var err error
	convertedAddr := addressing.AddressType(k8sAddress)

	switch convertedAddr {
	case addressing.NodeExternalDNS, addressing.NodeExternalIP, addressing.NodeHostName, addressing.NodeInternalIP, addressing.NodeInternalDNS:
	default:
		err = fmt.Errorf("invalid Kubernetes NodeAddressType %s", convertedAddr)
	}
	return convertedAddr, err
}

// ParseNode parses a kubernetes node to a cilium node
func ParseNode(k8sNode *slim_corev1.Node, source source.Source) *nodeTypes.Node {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName:  k8sNode.Name,
		logfields.K8sNodeID: k8sNode.UID,
	})
	addrs := []nodeTypes.Address{}
	for _, addr := range k8sNode.Status.Addresses {
		// We only care about this address types,
		// we ignore all other types.
		switch addr.Type {
		case slim_corev1.NodeInternalIP, slim_corev1.NodeExternalIP:
		default:
			continue
		}
		// If the address is not set let's not parse it at all.
		// This can be the case for corev1.NodeExternalIPs
		if addr.Address == "" {
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

		addressType, err := ParseNodeAddressType(addr.Type)

		if err != nil {
			scopedLog.WithError(err).Warn("invalid address type for node")
		}

		na := nodeTypes.Address{
			Type: addressType,
			IP:   ip,
		}
		addrs = append(addrs, na)
	}

	k8sNodeAddHostIP := func(annotation string) {
		if ciliumInternalIP, ok := k8sNode.Annotations[annotation]; !ok || ciliumInternalIP == "" {
			scopedLog.Debugf("Missing %s. Annotation required when IPSec Enabled", annotation)
		} else if ip := net.ParseIP(ciliumInternalIP); ip == nil {
			scopedLog.Debugf("ParseIP %s error", ciliumInternalIP)
		} else {
			na := nodeTypes.Address{
				Type: addressing.NodeCiliumInternalIP,
				IP:   ip,
			}
			addrs = append(addrs, na)
			scopedLog.Debugf("Add NodeCiliumInternalIP: %s", ip)
		}
	}

	k8sNodeAddHostIP(annotation.CiliumHostIP)
	k8sNodeAddHostIP(annotation.CiliumHostIPv6)

	encryptKey := uint8(0)
	if key, ok := k8sNode.Annotations[annotation.CiliumEncryptionKey]; ok {
		if u, err := strconv.ParseUint(key, 10, 8); err == nil {
			encryptKey = uint8(u)
		}
	}

	newNode := &nodeTypes.Node{
		Name:          k8sNode.Name,
		Cluster:       option.Config.ClusterName,
		IPAddresses:   addrs,
		Source:        source,
		EncryptionKey: encryptKey,
	}

	if len(k8sNode.Spec.PodCIDRs) != 0 {
		if len(k8sNode.Spec.PodCIDRs) > 2 {
			scopedLog.WithField("podCIDR", k8sNode.Spec.PodCIDRs).Errorf("Invalid PodCIDRs expected 1 or 2 PodCIDRs, received %d", len(k8sNode.Spec.PodCIDRs))
		} else {
			for _, podCIDR := range k8sNode.Spec.PodCIDRs {
				if allocCIDR, err := cidr.ParseCIDR(podCIDR); err != nil {
					scopedLog.WithError(err).WithField("podCIDR", k8sNode.Spec.PodCIDR).Warn("Invalid PodCIDR value for node")
				} else {
					if allocCIDR.IP.To4() != nil {
						newNode.IPv4AllocCIDR = allocCIDR
					} else {
						newNode.IPv6AllocCIDR = allocCIDR
					}
				}
			}
		}
	} else if len(k8sNode.Spec.PodCIDR) != 0 {
		if allocCIDR, err := cidr.ParseCIDR(k8sNode.Spec.PodCIDR); err != nil {
			scopedLog.WithError(err).WithField(logfields.V4Prefix, k8sNode.Spec.PodCIDR).Warn("Invalid PodCIDR value for node")
		} else {
			if allocCIDR.IP.To4() != nil {
				newNode.IPv4AllocCIDR = allocCIDR
			} else {
				newNode.IPv6AllocCIDR = allocCIDR
			}
		}
	}
	// Spec.PodCIDR takes precedence since it's
	// the CIDR assigned by k8s controller manager
	// In case it's invalid or empty then we fall back to our annotations.
	if newNode.IPv4AllocCIDR == nil {
		if ipv4CIDR, ok := k8sNode.Annotations[annotation.V4CIDRName]; !ok || ipv4CIDR == "" {
			scopedLog.Debug("Empty IPv4 CIDR annotation in node")
		} else {
			allocCIDR, err := cidr.ParseCIDR(ipv4CIDR)
			if err != nil {
				scopedLog.WithError(err).WithField(logfields.V4Prefix, ipv4CIDR).Error("BUG, invalid IPv4 annotation CIDR in node")
			} else {
				newNode.IPv4AllocCIDR = allocCIDR
			}
		}
	}

	if newNode.IPv6AllocCIDR == nil {
		if ipv6CIDR, ok := k8sNode.Annotations[annotation.V6CIDRName]; !ok || ipv6CIDR == "" {
			scopedLog.Debug("Empty IPv6 CIDR annotation in node")
		} else {
			allocCIDR, err := cidr.ParseCIDR(ipv6CIDR)
			if err != nil {
				scopedLog.WithError(err).WithField(logfields.V6Prefix, ipv6CIDR).Error("BUG, invalid IPv6 annotation CIDR in node")
			} else {
				newNode.IPv6AllocCIDR = allocCIDR
			}
		}
	}

	if newNode.IPv4HealthIP == nil {
		if healthIP, ok := k8sNode.Annotations[annotation.V4HealthName]; !ok || healthIP == "" {
			scopedLog.Debug("Empty IPv4 health endpoint annotation in node")
		} else if ip := net.ParseIP(healthIP); ip == nil {
			scopedLog.WithField(logfields.V4HealthIP, healthIP).Error("BUG, invalid IPv4 health endpoint annotation in node")
		} else {
			newNode.IPv4HealthIP = ip
		}
	}

	if newNode.IPv6HealthIP == nil {
		if healthIP, ok := k8sNode.Annotations[annotation.V6HealthName]; !ok || healthIP == "" {
			scopedLog.Debug("Empty IPv6 health endpoint annotation in node")
		} else if ip := net.ParseIP(healthIP); ip == nil {
			scopedLog.WithField(logfields.V6HealthIP, healthIP).Error("BUG, invalid IPv6 health endpoint annotation in node")
		} else {
			newNode.IPv6HealthIP = ip
		}
	}

	if newNode.IPv4IngressIP == nil {
		if ingressIP, ok := k8sNode.Annotations[annotation.V4IngressName]; !ok || ingressIP == "" {
			scopedLog.Debug("Empty IPv4 Ingress annotation in node")
		} else if ip := net.ParseIP(ingressIP); ip == nil {
			scopedLog.WithField(logfields.V4IngressIP, ingressIP).Error("BUG, invalid IPv4 Ingress annotation in node")
		} else {
			newNode.IPv4IngressIP = ip
		}
	}

	if newNode.IPv6IngressIP == nil {
		if ingressIP, ok := k8sNode.Annotations[annotation.V6IngressName]; !ok || ingressIP == "" {
			scopedLog.Debug("Empty IPv6 Ingress annotation in node")
		} else if ip := net.ParseIP(ingressIP); ip == nil {
			scopedLog.WithField(logfields.V6IngressIP, ingressIP).Error("BUG, invalid IPv6 Ingress annotation in node")
		} else {
			newNode.IPv6IngressIP = ip
		}
	}

	newNode.Labels = k8sNode.GetLabels()

	return newNode
}
