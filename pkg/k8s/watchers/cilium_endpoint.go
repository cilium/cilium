// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/cilium/hive/cell"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	hubblemetrics "github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type k8sCiliumEndpointsWatcherParams struct {
	cell.In

	Resources         agentK8s.Resources
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups

	EndpointManager endpointmanager.EndpointManager
	PolicyUpdater   *policy.Updater
	IPCache         *ipcache.IPCache
}

func newK8sCiliumEndpointsWatcher(params k8sCiliumEndpointsWatcherParams) *K8sCiliumEndpointsWatcher {
	return &K8sCiliumEndpointsWatcher{
		k8sResourceSynced: params.K8sResourceSynced,
		k8sAPIGroups:      params.K8sAPIGroups,
		resources:         params.Resources,
		endpointManager:   params.EndpointManager,
		policyManager:     params.PolicyUpdater,
		ipcache:           params.IPCache,
	}
}

type K8sCiliumEndpointsWatcher struct {
	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups

	endpointManager endpointManager
	policyManager   policyManager
	ipcache         ipcacheManager

	resources agentK8s.Resources
}

// initCiliumEndpointOrSlices initializes the ciliumEndpoints or ciliumEndpointSlice
func (k *K8sCiliumEndpointsWatcher) initCiliumEndpointOrSlices(ctx context.Context) {
	// If CiliumEndpointSlice feature is enabled, Cilium-agent watches CiliumEndpointSlice
	// objects instead of CiliumEndpoints. Hence, skip watching CiliumEndpoints if CiliumEndpointSlice
	// feature is enabled.
	if option.Config.EnableCiliumEndpointSlice {
		k.ciliumEndpointSliceInit(ctx)
	} else {
		k.ciliumEndpointsInit(ctx)
	}
}

func (k *K8sCiliumEndpointsWatcher) ciliumEndpointsInit(ctx context.Context) {
	var synced atomic.Bool

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		ctx.Done(),
		nil,
		func() bool { return synced.Load() },
		k8sAPIGroupCiliumEndpointV2,
	)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEndpointV2)

	go func() {
		events := k.resources.CiliumSlimEndpoint.Events(ctx)
		cache := make(map[resource.Key]*types.CiliumEndpoint)
		for event := range events {
			switch event.Kind {
			case resource.Sync:
				synced.Store(true)
			case resource.Upsert:
				oldObj, ok := cache[event.Key]
				if !ok || !oldObj.DeepEqual(event.Object) {
					k.endpointUpdated(oldObj, event.Object)
					cache[event.Key] = event.Object
				}
			case resource.Delete:
				k.endpointDeleted(event.Object)
				delete(cache, event.Key)
			}
			event.Done(nil)
		}
	}()
}

func (k *K8sCiliumEndpointsWatcher) endpointUpdated(oldEndpoint, endpoint *types.CiliumEndpoint) {
	var namedPortsChanged bool
	defer func() {
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates("Named ports added or updated")
		}
	}()
	var ipsAdded []string
	if oldEndpoint != nil && oldEndpoint.Networking != nil {
		// Delete the old IP addresses from the IP cache
		defer func() {
			for _, oldPair := range oldEndpoint.Networking.Addressing {
				v4Added, v6Added := false, false
				for _, ipAdded := range ipsAdded {
					if ipAdded == oldPair.IPV4 {
						v4Added = true
					}
					if ipAdded == oldPair.IPV6 {
						v6Added = true
					}
				}
				if !v4Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
				if !v6Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
			}
		}()
	}

	// default to the standard key
	encryptionKey := node.GetEndpointEncryptKeyIndex()

	id := identity.ReservedIdentityUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
	}

	if endpoint.Encryption != nil {
		encryptionKey = uint8(endpoint.Encryption.Key)
	}

	if endpoint.Networking == nil || endpoint.Networking.NodeIP == "" {
		// When upgrading from an older version, the nodeIP may
		// not be available yet in the CiliumEndpoint and we
		// have to wait for it to be propagated
		return
	}

	nodeIP := net.ParseIP(endpoint.Networking.NodeIP)
	if nodeIP == nil {
		log.WithField("nodeIP", endpoint.Networking.NodeIP).Warning("Unable to parse node IP while processing CiliumEndpoint update")
		return
	}

	k8sMeta := &ipcache.K8sMetadata{
		Namespace:  endpoint.Namespace,
		PodName:    endpoint.Name,
		NamedPorts: make(ciliumTypes.NamedPortMap, len(endpoint.NamedPorts)),
	}
	for _, port := range endpoint.NamedPorts {
		p, err := u8proto.ParseProtocol(port.Protocol)
		if err != nil {
			continue
		}
		k8sMeta.NamedPorts[port.Name] = ciliumTypes.PortProto{
			Port:  port.Port,
			Proto: p,
		}
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ipsAdded = append(ipsAdded, pair.IPV4)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV4, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}

		if pair.IPV6 != "" {
			ipsAdded = append(ipsAdded, pair.IPV6)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV6, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}
	}
}

func (k *K8sCiliumEndpointsWatcher) endpointDeleted(endpoint *types.CiliumEndpoint) {
	if endpoint.Networking != nil {
		namedPortsChanged := false
		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}

			if pair.IPV6 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}
		}
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates("Named ports deleted")
		}
	}
	hubblemetrics.ProcessCiliumEndpointDeletion(endpoint)
}
