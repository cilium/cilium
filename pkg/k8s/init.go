// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/backoff"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	k8sConst "github.com/cilium/cilium/pkg/k8s/constants"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

const (
	nodeRetrievalMaxRetries = 15
)

type nodeGetter interface {
	GetK8sNode(ctx context.Context, nodeName string) (*corev1.Node, error)
}

func waitForNodeInformation(ctx context.Context, nodeGetter nodeGetter, nodeName string) *nodeTypes.Node {
	backoff := backoff.Exponential{
		Min:    time.Duration(200) * time.Millisecond,
		Max:    2 * time.Minute,
		Factor: 2.0,
		Name:   "k8s-node-retrieval",
	}

	for retry := 0; retry < nodeRetrievalMaxRetries; retry++ {
		n, err := retrieveNodeInformation(ctx, nodeGetter, nodeName)
		if err != nil {
			log.WithError(err).Warning("Waiting for k8s node information")
			backoff.Wait(ctx)
			continue
		}

		return n
	}

	return nil
}

func retrieveNodeInformation(ctx context.Context, nodeGetter nodeGetter, nodeName string) (*nodeTypes.Node, error) {
	requireIPv4CIDR := option.Config.K8sRequireIPv4PodCIDR
	requireIPv6CIDR := option.Config.K8sRequireIPv6PodCIDR
	// At this point it's not clear whether the device auto-detection will
	// happen, as initKubeProxyReplacementOptions() might disable BPF NodePort.
	// Anyway, to be on the safe side, don't give up waiting for a (Cilium)Node
	// self object.
	mightAutoDetectDevices := option.MightAutoDetectDevices()
	var n *nodeTypes.Node

	if option.Config.IPAM == ipamOption.IPAMClusterPool || option.Config.IPAM == ipamOption.IPAMClusterPoolV2 {
		ciliumNode, err := CiliumClient().CiliumV2().CiliumNodes().Get(ctx, nodeName, v1.GetOptions{})
		if err != nil {
			// If no CIDR is required, retrieving the node information is
			// optional
			if !requireIPv4CIDR && !requireIPv6CIDR && !mightAutoDetectDevices {
				return nil, nil
			}

			return nil, fmt.Errorf("unable to retrieve CiliumNode: %s", err)
		}

		no := nodeTypes.ParseCiliumNode(ciliumNode)
		n = &no
		log.WithField(logfields.NodeName, n.Name).Info("Retrieved node information from cilium node")
	} else {
		k8sNode, err := nodeGetter.GetK8sNode(ctx, nodeName)
		if err != nil {
			// If no CIDR is required, retrieving the node information is
			// optional
			if !requireIPv4CIDR && !requireIPv6CIDR && !mightAutoDetectDevices {
				return nil, nil
			}

			return nil, fmt.Errorf("unable to retrieve k8s node information: %s", err)

		}

		nodeInterface := ConvertToNode(k8sNode)
		if nodeInterface == nil {
			// This will never happen and the GetNode on line 63 will be soon
			// make a request from the local store instead.
			return nil, fmt.Errorf("invalid k8s node: %s", k8sNode)
		}
		typesNode := nodeInterface.(*slim_corev1.Node)

		// The source is left unspecified as this node resource should never be
		// used to update state
		n = ParseNode(typesNode, source.Unspec)
		log.WithField(logfields.NodeName, n.Name).Info("Retrieved node information from kubernetes node")
	}

	if requireIPv4CIDR && n.IPv4AllocCIDR == nil {
		return nil, fmt.Errorf("required IPv4 PodCIDR not available")
	}

	if requireIPv6CIDR && n.IPv6AllocCIDR == nil {
		return nil, fmt.Errorf("required IPv6 PodCIDR not available")
	}

	return n, nil
}

// Init initializes the Kubernetes package. It is required to call Configure()
// beforehand.
func Init(conf k8sconfig.Configuration) error {
	cfg := client.Config{
		K8sAPIServer:      GetAPIServerURL(),
		K8sKubeConfigPath: GetKubeconfigPath(),
		K8sClientQPS:      GetQPS(),
		K8sClientBurst:    GetBurst(),
	}

	clientset, err := client.NewStandaloneClientset(cfg)
	if err != nil {
		return err
	}

	SetClients(clientset, clientset.Slim(), clientset, clientset)

	if err := k8sversion.Update(Client(), conf); err != nil {
		return err
	}

	if !k8sversion.Capabilities().MinimalVersionMet {
		return fmt.Errorf("k8s version (%v) is not meeting the minimal requirement (%v)",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	return nil
}

// WaitForNodeInformation retrieves the node information via the CiliumNode or
// Kubernetes Node resource. This function will block until the information is
// received. nodeGetter is a function used to retrieved the node from either
// the kube-apiserver or a local cache, depending on the caller.
func WaitForNodeInformation(ctx context.Context, nodeGetter nodeGetter) (*nodeTypes.Node, error) {
	// Use of the environment variable overwrites the node-name
	// automatically derived
	nodeName := nodeTypes.GetName()
	if nodeName == "" {
		if option.Config.K8sRequireIPv4PodCIDR || option.Config.K8sRequireIPv6PodCIDR {
			return nil, fmt.Errorf("node name must be specified via environment variable '%s' to retrieve Kubernetes PodCIDR range", k8sConst.EnvNodeNameSpec)
		}
		if option.MightAutoDetectDevices() {
			log.Info("K8s node name is empty. BPF NodePort might not be able to auto detect all devices")
		}
		return nil, nil
	}

	if n := waitForNodeInformation(ctx, nodeGetter, nodeName); n != nil {

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

		return n, nil
	} else {
		// if node resource could not be received, fail if
		// PodCIDR requirement has been requested
		if option.Config.K8sRequireIPv4PodCIDR || option.Config.K8sRequireIPv6PodCIDR {
			log.Fatal("Unable to derive PodCIDR via Node or CiliumNode resource, giving up")
		}
	}

	// Annotate addresses will occur later since the user might
	// want to specify them manually
	return nil, nil
}
