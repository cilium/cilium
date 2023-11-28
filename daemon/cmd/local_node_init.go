// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"

	k8sLabels "k8s.io/apimachinery/pkg/labels"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

type localNodeInitializerParams struct {
	cell.In

	Config             *option.DaemonConfig
	Clientset          client.Clientset
	LocalNode          agentK8s.LocalNodeResource
	K8sCiliumLocalNode agentK8s.LocalCiliumNodeResource
}

// localNodeInitializer performs the bootstrapping of the LocalNodeStore,
// which contains information about the local Cilium node populated from
// configuration and Kubernetes.
type localNodeInitializer struct {
	localNodeInitializerParams
}

func (ini *localNodeInitializer) InitLocalNode(ctx context.Context, n *node.LocalNode) error {
	n.Source = source.Local

	if err := ini.initFromConfig(ctx, n); err != nil {
		return err
	}

	if err := ini.initFromK8s(ctx, n); err != nil {
		return err
	}
	return nil
}

func newLocalNodeInitializer(p localNodeInitializerParams) node.LocalNodeInitializer {
	return &localNodeInitializer{p}
}

func (ini *localNodeInitializer) initFromConfig(ctx context.Context, n *node.LocalNode) error {
	// If there is one device specified, use it to derive better default
	// allocation prefixes
	node.SetDefaultPrefix(ini.Config, ini.Config.DirectRoutingDevice, n)

	// Initialize node IP addresses from configuration.
	if ini.Config.IPv6NodeAddr != "auto" {
		if ip := net.ParseIP(ini.Config.IPv6NodeAddr); ip == nil {
			return fmt.Errorf("invalid IPv6 node address: %q", ini.Config.IPv6NodeAddr)
		} else {
			if !ip.IsGlobalUnicast() {
				return fmt.Errorf("Invalid IPv6 node address: %q not a global unicast address", ip)
			}
			n.SetNodeInternalIP(ip)
		}
	}
	if ini.Config.IPv4NodeAddr != "auto" {
		if ip := net.ParseIP(ini.Config.IPv4NodeAddr); ip == nil {
			return fmt.Errorf("Invalid IPv4 node address: %q", ini.Config.IPv4NodeAddr)
		} else {
			n.SetNodeInternalIP(ip)
		}
	}
	return nil
}

func (ini *localNodeInitializer) getK8sLocalNode(ctx context.Context) (*slim_corev1.Node, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for ev := range ini.LocalNode.Events(ctx) {
		ev.Done(nil)
		if ev.Kind == resource.Upsert {
			return ev.Object, nil
		}
	}
	return nil, ctx.Err()
}

// getK8sLocalCiliumNode returns the CiliumNode object for the local node if it exists at the type
// of the call.
// In the case that the resource event is synced without a ciliumnode upsert event, we return nil.
func (ini *localNodeInitializer) getK8sLocalCiliumNode(ctx context.Context) *v2.CiliumNode {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil
	case ev := <-ini.K8sCiliumLocalNode.Events(ctx):
		ev.Done(nil)
		switch ev.Kind {
		case resource.Upsert:
			return ev.Object
		case resource.Sync:
			log.Debug("sync event received before local ciliumnode upsert, skipping ciliumnode sync")
			return nil
		}
	}
	return nil
}

func (ini *localNodeInitializer) initFromK8s(ctx context.Context, node *node.LocalNode) error {
	if ini.LocalNode == nil {
		return nil
	}

	k8sNode, err := ini.getK8sLocalNode(ctx)
	if err != nil {
		return err
	}
	parsedNode := k8s.ParseNode(k8sNode, source.Kubernetes)

	// Initialize the fields in local node where the source of truth is in Kubernetes.
	// Later stages will deal with updating rest of the fields depending on configuration.
	//
	// The fields left uninitialized/unrestored here:
	//   - Cilium internal IPs (restored from cilium_host or allocated by IPAM)
	//   - Health IPs (allocated by IPAM)
	//   - Ingress IPs (restored from ipcachemap or allocated)
	//   - Wireguard key (set by wireguard agent)
	//   - IPsec key (set by IPsec)
	//   - alloc CIDRs (depends on IPAM mode; restored from Node or CiliumNode)
	//   - ClusterID (set by NodeDiscovery)
	//   - NodeIdentity (always unset)
	node.Name = parsedNode.Name
	node.Labels = parsedNode.Labels
	node.Annotations = parsedNode.Annotations
	node.Cluster = parsedNode.Cluster
	for _, addr := range parsedNode.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			node.SetNodeInternalIP(addr.IP)
		} else if addr.Type == addressing.NodeExternalIP {
			node.SetNodeExternalIP(addr.IP)
		}
	}

	// In cases where no local CiliumNode exists (such as on a fresh node) we skip restoring
	// the CiliumNode information from k8s.
	k8sCiliumNode := ini.getK8sLocalCiliumNode(ctx)
	if k8sCiliumNode != nil {
		for _, addr := range k8sCiliumNode.Spec.Addresses {
			if addr.Type == addressing.NodeCiliumInternalIP {
				node.SetCiliumInternalIP(net.ParseIP(addr.IP))
			}
		}
	} else {
		log.Info("no local ciliumnode found, will not restore cilium internal ips from k8s")
	}
	if ini.Config.NodeEncryptionOptOutLabels.Matches(k8sLabels.Set(node.Labels)) {
		log.WithField(logfields.Selector, ini.Config.NodeEncryptionOptOutLabels).
			Infof("Opting out from node-to-node encryption on this node as per '%s' label selector",
				option.NodeEncryptionOptOutLabels)
		node.OptOutNodeEncryption = true
	}

	return nil
}
