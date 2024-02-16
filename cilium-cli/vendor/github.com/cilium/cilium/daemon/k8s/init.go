// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/constants"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

func retrieveNodeInformation(ctx context.Context, log logrus.FieldLogger, localNodeResource LocalNodeResource, localCiliumNodeResource LocalCiliumNodeResource) *nodeTypes.Node {
	var n *nodeTypes.Node
	waitForCIDR := func() error {
		if option.Config.K8sRequireIPv4PodCIDR && n.IPv4AllocCIDR == nil {
			return fmt.Errorf("required IPv4 PodCIDR not available")
		}
		if option.Config.K8sRequireIPv6PodCIDR && n.IPv6AllocCIDR == nil {
			return fmt.Errorf("required IPv6 PodCIDR not available")
		}
		return nil
	}

	if option.Config.IPAM == ipamOption.IPAMClusterPool {
		for event := range localCiliumNodeResource.Events(ctx) {
			if event.Kind == resource.Upsert {
				no := nodeTypes.ParseCiliumNode(event.Object)
				n = &no
				log.WithField(logfields.NodeName, n.Name).Info("Retrieved node information from cilium node")
				if err := waitForCIDR(); err != nil {
					log.WithError(err).Warning("Waiting for k8s node information")
				} else {
					event.Done(nil)
					break
				}
			}
			event.Done(nil)
		}
	} else {
		for event := range localNodeResource.Events(ctx) {
			if event.Kind == resource.Upsert {
				n = k8s.ParseNode(event.Object, source.Unspec)
				log.WithField(logfields.NodeName, n.Name).Info("Retrieved node information from kubernetes node")
				if err := waitForCIDR(); err != nil {
					log.WithError(err).Warning("Waiting for k8s node information")
				} else {
					event.Done(nil)
					break
				}
			}
			event.Done(nil)
		}
	}

	return n
}

// useNodeCIDR sets the ipv4-range and ipv6-range values values from the
// addresses defined in the given node.
func useNodeCIDR(n *nodeTypes.Node) {
	if n.IPv4AllocCIDR != nil && option.Config.EnableIPv4 {
		node.SetIPv4AllocRange(n.IPv4AllocCIDR)
	}
	if n.IPv6AllocCIDR != nil && option.Config.EnableIPv6 {
		node.SetIPv6NodeRange(n.IPv6AllocCIDR)
	}
}

// WaitForNodeInformation retrieves the node information via the CiliumNode or
// Kubernetes Node resource. This function will block until the information is
// received.
func WaitForNodeInformation(ctx context.Context, log logrus.FieldLogger, localNode LocalNodeResource, localCiliumNode LocalCiliumNodeResource) error {
	// Use of the environment variable overwrites the node-name
	// automatically derived
	nodeName := nodeTypes.GetName()
	if nodeName == "" {
		if option.Config.K8sRequireIPv4PodCIDR || option.Config.K8sRequireIPv6PodCIDR {
			return fmt.Errorf("node name must be specified via environment variable '%s' to retrieve Kubernetes PodCIDR range", k8sConst.EnvNodeNameSpec)
		}
		if option.MightAutoDetectDevices() {
			log.Info("K8s node name is empty. BPF NodePort might not be able to auto detect all devices")
		}
		return nil
	}

	requireIPv4CIDR := option.Config.K8sRequireIPv4PodCIDR
	requireIPv6CIDR := option.Config.K8sRequireIPv6PodCIDR
	// If no CIDR is required, retrieving the node information is
	// optional
	// At this point it's not clear whether the device auto-detection will
	// happen, as initKubeProxyReplacementOptions() might disable BPF NodePort.
	// Anyway, to be on the safe side, don't give up waiting for a (Cilium)Node
	// self object.
	isNodeInformationOptional := (!requireIPv4CIDR && !requireIPv6CIDR && !option.MightAutoDetectDevices())
	// If node information is optional, let's wait 10 seconds only.
	// It node information is required, wait indefinitely.
	if isNodeInformationOptional {
		newCtx, cancel := context.WithTimeout(ctx, time.Second*10)
		ctx = newCtx
		defer cancel()
	}

	if n := retrieveNodeInformation(ctx, log, localNode, localCiliumNode); n != nil {
		nodeIP4 := n.GetNodeIP(false)
		nodeIP6 := n.GetNodeIP(true)
		k8sNodeIP := n.GetK8sNodeIP()

		log.WithFields(logrus.Fields{
			logfields.NodeName:         n.Name,
			logfields.Labels:           logfields.Repr(n.Labels),
			logfields.IPAddr + ".ipv4": nodeIP4,
			logfields.IPAddr + ".ipv6": nodeIP6,
			logfields.V4Prefix:         n.IPv4AllocCIDR,
			logfields.V6Prefix:         n.IPv6AllocCIDR,
			logfields.K8sNodeIP:        k8sNodeIP,
		}).Info("Received own node information from API server")

		useNodeCIDR(n)
		restoreRouterHostIPs(n, log)
	} else {
		// if node resource could not be received, fail if
		// PodCIDR requirement has been requested
		if requireIPv4CIDR || requireIPv6CIDR {
			return fmt.Errorf("unable to derive PodCIDR via Node or CiliumNode resource")
		}
	}

	// Annotate addresses will occur later since the user might
	// want to specify them manually
	return nil
}

// restoreRouterHostIPs restores (sets) the router IPs found from the
// Kubernetes resource.
//
// Note that it does not validate the correctness of the IPs, as that is done
// later in the daemon initialization when node.AutoComplete() is called.
func restoreRouterHostIPs(n *nodeTypes.Node, log logrus.FieldLogger) {
	if !option.Config.EnableHostIPRestore {
		return
	}

	router4 := n.GetCiliumInternalIP(false)
	router6 := n.GetCiliumInternalIP(true)
	if router4 != nil {
		node.SetInternalIPv4Router(router4)
	}
	if router6 != nil {
		node.SetIPv6Router(router6)
	}
	if router4 != nil || router6 != nil {
		log.WithFields(logrus.Fields{
			logfields.IPv4: router4,
			logfields.IPv6: router6,
		}).Info("Restored router IPs from node information")
	}
}
