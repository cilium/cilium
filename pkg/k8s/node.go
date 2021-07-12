// Copyright 2016-2021 Authors of Cilium
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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// ciliumNodeConditionReason is the condition name used by Cilium to set
	// when the Network is setup in the node.
	ciliumNodeConditionReason = "CiliumIsUp"
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

	newNode.Labels = k8sNode.GetLabels()

	return newNode
}

// setNodeNetworkUnavailableFalse sets Kubernetes NodeNetworkUnavailable to
// false as Cilium is managing the network connectivity.
// https://kubernetes.io/docs/concepts/architecture/nodes/#condition
func setNodeNetworkUnavailableFalse(ctx context.Context, c kubernetes.Interface, nodeGetter nodeGetter, nodeName string) error {
	n, err := nodeGetter.GetK8sNode(ctx, nodeName)
	if err != nil {
		return err
	}

	if HasCiliumIsUpCondition(n) {
		return nil
	}

	condition := corev1.NodeCondition{
		Type:               corev1.NodeNetworkUnavailable,
		Status:             corev1.ConditionFalse,
		Reason:             ciliumNodeConditionReason,
		Message:            "Cilium is running on this node",
		LastTransitionTime: metav1.Now(),
		LastHeartbeatTime:  metav1.Now(),
	}
	raw, err := json.Marshal(&[]corev1.NodeCondition{condition})
	if err != nil {
		return err
	}
	patch := []byte(fmt.Sprintf(`{"status":{"conditions":%s}}`, raw))
	_, err = c.CoreV1().Nodes().PatchStatus(context.TODO(), nodeName, patch)
	return err
}

// HasCiliumIsUpCondition returns true if the given k8s node has the cilium node
// condition set.
func HasCiliumIsUpCondition(n *corev1.Node) bool {
	for _, condition := range n.Status.Conditions {
		if condition.Type == corev1.NodeNetworkUnavailable &&
			condition.Status == corev1.ConditionFalse &&
			condition.Reason == ciliumNodeConditionReason {
			return true
		}
	}
	return false
}

// removeNodeTaint removes the AgentNotReadyNodeTaint allowing for pods to be
// scheduled once Cilium is setup. Mostly used in cloud providers to prevent
// existing CNI plugins from managing pods.
func removeNodeTaint(ctx context.Context, c kubernetes.Interface, nodeGetter nodeGetter, nodeName string) error {
	k8sNode, err := nodeGetter.GetK8sNode(ctx, nodeName)
	if err != nil {
		return err
	}

	var taintFound bool

	var taints []corev1.Taint
	for _, taint := range k8sNode.Spec.Taints {
		if taint.Key != ciliumio.AgentNotReadyNodeTaint {
			taints = append(taints, taint)
		} else {
			taintFound = true
		}
	}

	// No cilium taints found
	if !taintFound {
		log.WithFields(logrus.Fields{
			logfields.NodeName: nodeName,
			"taint":            ciliumio.AgentNotReadyNodeTaint,
		}).Debug("Taint not found in node")
		return nil
	}
	log.WithFields(logrus.Fields{
		logfields.NodeName: nodeName,
		"taint":            ciliumio.AgentNotReadyNodeTaint,
	}).Debug("Removing Node Taint")

	k8sNode.Spec.Taints = taints

	_, err = c.CoreV1().Nodes().Update(ctx, k8sNode, metav1.UpdateOptions{})
	return err
}

const (
	markK8sNodeReadyControllerName = "mark-k8s-node-as-available"
)

// MarkNodeReady marks the Kubernetes node resource as ready from a networking
// perspective
func (k8sCli K8sClient) MarkNodeReady(nodeGetter nodeGetter, nodeName string) {
	log.WithField(logfields.NodeName, nodeName).Debug("Setting NetworkUnavailable=false")

	controller.NewManager().UpdateController(markK8sNodeReadyControllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				err := removeNodeTaint(ctx, k8sCli, nodeGetter, nodeName)
				if err != nil {
					return err
				}
				return setNodeNetworkUnavailableFalse(ctx, k8sCli, nodeGetter, nodeName)
			},
		})
}

// ReMarkNodeReady re-triggers the controller set by 'MarkNodeReady'. If
// 'MarkNodeReady' has not been executed yet, calling this function be a no-op.
func (k8sCli K8sClient) ReMarkNodeReady() {
	controller.NewManager().TriggerController(markK8sNodeReadyControllerName)
}
