// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func (k *K8sWatcher) ciliumEndpointsInit(ctx context.Context, asyncControllers *sync.WaitGroup) {
	// CiliumEndpoint objects are used for ipcache discovery until the
	// key-value store is connected
	var once sync.Once
	apiGroup := k8sAPIGroupCiliumEndpointV2

	for {
		var synced atomic.Bool
		stop := make(chan struct{})

		k.blockWaitGroupToSyncResources(
			stop,
			nil,
			func() bool { return synced.Load() },
			apiGroup,
		)
		k.k8sAPIGroups.AddAPI(apiGroup)

		// Signalize that we have put node controller in the wait group to sync resources.
		once.Do(asyncControllers.Done)

		// derive another context to signal Events() in case of kvstore connection
		eventsCtx, cancel := context.WithCancel(ctx)

		go func() {
			defer close(stop)

			events := k.resources.CiliumSlimEndpoint.Events(eventsCtx)
			cache := make(map[resource.Key]*types.CiliumEndpoint)
			for event := range events {
				var err error
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
				event.Done(err)
			}
		}()

		select {
		case <-kvstore.Connected():
			log.Info("Connected to key-value store, stopping CiliumEndpoint watcher")
			cancel()
			k.cancelWaitGroupToSyncResources(apiGroup)
			k.k8sAPIGroups.RemoveAPI(apiGroup)
			<-stop
		case <-ctx.Done():
			cancel()
			<-stop
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-kvstore.Client().Disconnected():
			log.Info("Disconnected from key-value store, restarting CiliumEndpoint watcher")
		}
	}
}

func (k *K8sWatcher) endpointUpdated(oldEndpoint, endpoint *types.CiliumEndpoint) {
	var ipsAdded []string
	if oldEndpoint != nil && oldEndpoint.Networking != nil {
		// Delete the old IP addresses from the IP cache
		defer func() {
			k.removeEndpointIPCacheMetadata(oldEndpoint, ipsAdded)
		}()
	}

	id := identity.ReservedIdentityUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
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

	if option.Config.EnableHighScaleIPcache &&
		!identity.IsWellKnownIdentity(id) {
		// Well-known identities are kept in the high-scale ipcache because we
		// need to be able to connect to the DNS pods to resolve FQDN policies.
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Identity: id,
		})
		scopedLog.Debug("Endpoint is not well-known; skipping ipcache upsert")
		return
	}

	ipsAdded = append(ipsAdded, k.upsertEndpointIPCacheMetadata(endpoint)...)
}

func (k *K8sWatcher) endpointDeleted(endpoint *types.CiliumEndpoint) {
	k.removeEndpointIPCacheMetadata(endpoint, nil)
}

func (k *K8sWatcher) upsertEndpointIPCacheMetadata(endpoint *types.CiliumEndpoint) []string {
	id := identity.ReservedIdentityUnmanaged
	epLabels := labels.LabelUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
		epLabels = labels.NewLabelsFromModel(endpoint.Identity.Labels)
	}

	nodeIP := netip.MustParseAddr(endpoint.Networking.NodeIP)

	// default to the standard key
	encryptionKey := node.GetEndpointEncryptKeyIndex()
	if endpoint.Encryption != nil {
		encryptionKey = uint8(endpoint.Encryption.Key)
	}

	k8sMeta := ipcachetypes.K8sMetadata{
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
			Proto: uint8(p),
		}
	}

	var ipsAdded []string
	rid := ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCEP, endpoint.Namespace, endpoint.Name)
	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			if len(epLabels) == 0 {
				epLabels = k.getLabelsForIP(pair.IPV4, id)
			}

			ipsAdded = append(ipsAdded, pair.IPV4)
			prefix := ip.IPToNetPrefix(net.ParseIP(pair.IPV4))
			k.ipcache.UpsertMetadata(
				prefix,
				source.CustomResource,
				rid,
				// Metadata:
				epLabels,
				ipcachetypes.OverrideIdentity(true),
				ipcachetypes.TunnelPeer{Addr: nodeIP},
				ipcachetypes.EncryptKey(encryptionKey),
				ipcachetypes.RequestedIdentity(id),
				ipcachetypes.K8sMetadata(k8sMeta),
			)
		}

		if pair.IPV6 != "" {
			if len(epLabels) == 0 {
				epLabels = k.getLabelsForIP(pair.IPV6, id)
			}

			ipsAdded = append(ipsAdded, pair.IPV6)
			prefix := ip.IPToNetPrefix(net.ParseIP(pair.IPV6))
			k.ipcache.UpsertMetadata(
				prefix,
				source.CustomResource,
				rid,
				// Metadata:
				epLabels,
				ipcachetypes.OverrideIdentity(true),
				ipcachetypes.TunnelPeer{Addr: nodeIP},
				ipcachetypes.EncryptKey(encryptionKey),
				ipcachetypes.RequestedIdentity(id),
				ipcachetypes.K8sMetadata(k8sMeta),
			)
		}
	}

	return ipsAdded
}

func (k *K8sWatcher) getLabelsForIP(ip string, id identity.NumericIdentity) labels.Labels {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	epid := k.identityManager.LookupIdentityByID(ctx, id)
	if epid == nil {
		log.WithField(logfields.IPAddr, ip).Warning("Unable to find identity mapping to IP address for CEP ipcache metadata")
		return nil
	}
	return epid.Labels
}

func (k *K8sWatcher) removeEndpointIPCacheMetadata(endpoint *types.CiliumEndpoint, ipsAdded []string) {
	id := identity.ReservedIdentityUnmanaged
	epLabels := labels.LabelUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
		epLabels = labels.NewLabelsFromModel(endpoint.Identity.Labels)
	}

	nodeIP := netip.MustParseAddr(endpoint.Networking.NodeIP)

	// default to the standard key
	encryptionKey := node.GetEndpointEncryptKeyIndex()
	if endpoint.Encryption != nil {
		encryptionKey = uint8(endpoint.Encryption.Key)
	}

	k8sMeta := ipcachetypes.K8sMetadata{
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
			Proto: uint8(p),
		}
	}

	rid := ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCEP, endpoint.Namespace, endpoint.Name)
	for _, oldPair := range endpoint.Networking.Addressing {
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
			prefix := ip.IPToNetPrefix(net.ParseIP(oldPair.IPV4))
			k.ipcache.RemoveMetadata(
				prefix,
				rid,
				// Metadata:
				epLabels,
				ipcachetypes.OverrideIdentity(true),
				ipcachetypes.TunnelPeer{Addr: nodeIP},
				ipcachetypes.EncryptKey(encryptionKey),
				ipcachetypes.RequestedIdentity(id),
				ipcachetypes.K8sMetadata(k8sMeta),
			)
		}
		if !v6Added {
			prefix := ip.IPToNetPrefix(net.ParseIP(oldPair.IPV6))
			k.ipcache.RemoveMetadata(
				prefix,
				rid,
				// Metadata:
				epLabels,
				ipcachetypes.OverrideIdentity(true),
				ipcachetypes.TunnelPeer{Addr: nodeIP},
				ipcachetypes.EncryptKey(encryptionKey),
				ipcachetypes.RequestedIdentity(id),
				ipcachetypes.K8sMetadata(k8sMeta),
			)
		}
	}
}
