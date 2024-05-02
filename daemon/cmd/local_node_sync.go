// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/hive/cell"
	"golang.org/x/exp/maps"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	wg "github.com/cilium/cilium/pkg/wireguard/agent"
)

type localNodeSynchronizerParams struct {
	cell.In

	Config             *option.DaemonConfig
	K8sLocalNode       agentK8s.LocalNodeResource
	K8sCiliumLocalNode agentK8s.LocalCiliumNodeResource

	WireGuard *wg.Agent // nil if WireGuard is disabled
}

// localNodeSynchronizer performs the bootstrapping of the LocalNodeStore,
// which contains information about the local Cilium node populated from
// configuration and Kubernetes. Additionally, it also takes care of keeping
// the selected fields of the LocalNodeStore synchronized with Kubernetes.
type localNodeSynchronizer struct {
	localNodeSynchronizerParams
	old node.LocalNode
}

func (ini *localNodeSynchronizer) InitLocalNode(ctx context.Context, n *node.LocalNode) error {
	n.Source = source.Local
	n.NodeIdentity = uint32(identity.ReservedIdentityHost)

	if err := ini.initFromConfig(ctx, n); err != nil {
		return err
	}

	if err := ini.initFromK8s(ctx, n); err != nil {
		return err
	}

	if ini.WireGuard != nil {
		ini.WireGuard.InitLocalNodeFromWireGuard(n)
	}

	n.BootID = node.GetBootID()
	if option.Config.EnableIPSec && n.BootID == "" {
		return fmt.Errorf("IPSec requires a valid BootID")
	}

	return nil
}

func (ini *localNodeSynchronizer) SyncLocalNode(ctx context.Context, store *node.LocalNodeStore) {
	if ini.K8sLocalNode == nil {
		return
	}

	for ev := range ini.K8sLocalNode.Events(ctx) {
		if ev.Kind == resource.Upsert {
			new := parseNode(ev.Object)
			if !ini.mutableFieldsEqual(new) {
				store.Update(func(ln *node.LocalNode) {
					ini.syncFromK8s(ln, new)
				})
			}
		}

		ev.Done(nil)
	}
}

func newLocalNodeSynchronizer(p localNodeSynchronizerParams) node.LocalNodeSynchronizer {
	return &localNodeSynchronizer{localNodeSynchronizerParams: p}
}

func (ini *localNodeSynchronizer) initFromConfig(ctx context.Context, n *node.LocalNode) error {
	n.Cluster = ini.Config.ClusterName
	n.ClusterID = ini.Config.ClusterID
	n.Name = nodeTypes.GetName()

	n.IPv4NativeRoutingCIDR = ini.Config.IPv4NativeRoutingCIDR
	n.IPv6NativeRoutingCIDR = ini.Config.IPv6NativeRoutingCIDR

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

func (ini *localNodeSynchronizer) getK8sLocalNode(ctx context.Context) (*slim_corev1.Node, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for ev := range ini.K8sLocalNode.Events(ctx) {
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
func (ini *localNodeSynchronizer) getK8sLocalCiliumNode(ctx context.Context) *v2.CiliumNode {
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

func (ini *localNodeSynchronizer) initFromK8s(ctx context.Context, node *node.LocalNode) error {
	if ini.K8sLocalNode == nil {
		return nil
	}

	k8sNode, err := ini.getK8sLocalNode(ctx)
	if err != nil {
		return err
	}
	parsedNode := parseNode(k8sNode)

	// Initialize the fields in local node where the source of truth is in Kubernetes.
	// Later stages will deal with updating rest of the fields depending on configuration.
	//
	// The fields left uninitialized/unrestored here:
	//   - Cilium internal IPs (restored from cilium_host or allocated by IPAM)
	//   - Health IPs (allocated by IPAM)
	//   - Ingress IPs (restored from ipcachemap or allocated)
	//   - WireGuard key (set by WireGuard agent)
	//   - IPsec key (set by IPsec)
	//   - alloc CIDRs (depends on IPAM mode; restored from Node or CiliumNode)
	node.Name = parsedNode.Name
	for _, addr := range parsedNode.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			node.SetNodeInternalIP(addr.IP)
		} else if addr.Type == addressing.NodeExternalIP {
			node.SetNodeExternalIP(addr.IP)
		}
	}
	ini.syncFromK8s(node, parsedNode)

	// In cases where no local CiliumNode exists (such as on a fresh node) we skip restoring
	// the CiliumNode information from k8s.
	k8sCiliumNode := ini.getK8sLocalCiliumNode(ctx)
	if k8sCiliumNode != nil {
		for _, addr := range k8sCiliumNode.Spec.Addresses {
			if addr.Type == addressing.NodeCiliumInternalIP {
				node.SetCiliumInternalIP(net.ParseIP(addr.IP))
			}
		}

		if ini.Config.EnableHealthChecking && ini.Config.EnableEndpointHealthChecking {
			if ini.Config.EnableIPv4 {
				node.IPv4HealthIP = net.ParseIP(k8sCiliumNode.Spec.HealthAddressing.IPv4)
			}

			if ini.Config.EnableIPv6 {
				node.IPv6HealthIP = net.ParseIP(k8sCiliumNode.Spec.HealthAddressing.IPv6)
			}
		}
	} else {
		log.Info("no local ciliumnode found, will not restore cilium internal and health ips from k8s")
	}

	return nil
}

func (ini *localNodeSynchronizer) mutableFieldsEqual(new *node.LocalNode) bool {
	return maps.Equal(ini.old.Labels, new.Labels) &&
		maps.Equal(ini.old.Annotations, new.Annotations) &&
		ini.old.UID == new.UID && ini.old.ProviderID == new.ProviderID
}

// syncFromK8s synchronizes the fields that can be mutated at runtime
func (ini *localNodeSynchronizer) syncFromK8s(ln, new *node.LocalNode) {
	filter := func(old, new map[string]string, key string) bool {
		_, oldExists := old[key]
		_, newExists := new[key]
		return oldExists && !newExists
	}

	// Create a clone, so that we don't mutate the current labels/annotations,
	// as LocalNodeStore.Update emits a shallow copy of the whole object.
	ln.Labels = maps.Clone(ln.Labels)
	maps.DeleteFunc(ln.Labels, func(key, _ string) bool { return filter(ini.old.Labels, new.Labels, key) })
	maps.Copy(ln.Labels, new.Labels)
	ini.old.Labels = new.Labels

	ln.Annotations = maps.Clone(ln.Annotations)
	maps.DeleteFunc(ln.Annotations, func(key, _ string) bool { return filter(ini.old.Annotations, new.Annotations, key) })
	maps.Copy(ln.Annotations, new.Annotations)
	ini.old.Annotations = new.Annotations

	ini.old.UID = new.UID
	ini.old.ProviderID = new.ProviderID
	ln.UID = new.UID
	ln.ProviderID = new.ProviderID
}

func parseNode(k8sNode *slim_corev1.Node) *node.LocalNode {
	return &node.LocalNode{
		Node:       *k8s.ParseNode(k8sNode, source.Kubernetes),
		UID:        k8sNode.GetUID(),
		ProviderID: k8sNode.Spec.ProviderID,
	}
}
