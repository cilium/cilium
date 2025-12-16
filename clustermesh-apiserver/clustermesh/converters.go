// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"errors"
	"iter"
	"log/slog"
	"maps"
	"net"
	"path"
	"slices"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// noneIter is a zero-length [Seq].
func noneIter[T any](func(T) bool) {}

// singleIter returns a [Seq] of length one that yields the given value.
func singleIter[T any](value T) iter.Seq[T] {
	return func(yield func(T) bool) {
		yield(value)
	}
}

// ----- Generic ----- //

// CachedConverter implements the common logic of a converter that, given a single
// Kubernetes resource, returns multiple kvstore entries.
type CachedConverter[T runtime.Object] struct {
	// mapper knows how to map a Kubernetes resource to the corresponding kvstore entries.
	mapper func(T) iter.Seq[store.Key]
	// cache remembers the kvstore keys associated with any Kubernetes resource.
	cache map[resource.Key]sets.Set[string]
}

func NewCachedCoverter[T runtime.Object](mapper func(T) iter.Seq[store.Key]) *CachedConverter[T] {
	return &CachedConverter[T]{
		mapper: mapper,
		cache:  make(map[resource.Key]sets.Set[string]),
	}
}

func (ec *CachedConverter[T]) Convert(event resource.Event[T]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
	if event.Kind == resource.Delete {
		toDelete := maps.Keys(ec.cache[event.Key])
		delete(ec.cache, event.Key)
		return noneIter[store.Key], ec.deletesIter(toDelete)
	}

	var (
		toAdd    []store.Key
		toDelete = ec.cache[event.Key]
		current  = sets.New[string]()
	)

	for entry := range ec.mapper(event.Object) {
		key := entry.GetKeyName()
		toAdd = append(toAdd, entry)
		current.Insert(key)
		toDelete.Delete(key)
	}

	ec.cache[event.Key] = current
	return slices.Values(toAdd), ec.deletesIter(maps.Keys(toDelete))
}

func (ec *CachedConverter[T]) deletesIter(keys iter.Seq[string]) iter.Seq[store.NamedKey] {
	return func(yield func(store.NamedKey) bool) {
		for key := range keys {
			if !yield(store.NewKVPair(key, "")) {
				return
			}
		}
	}
}

// ----- CiliumNodes ----- //

func newCiliumNodeOptions() Options[*cilium_api_v2.CiliumNode] {
	return Options[*cilium_api_v2.CiliumNode]{
		Enabled:  true,
		Resource: "CiliumNode",
		Prefix:   nodeStore.NodeStorePrefix,
	}
}

// CiliumNodeConverter implements Converter[*cilium_api_v2.CiliumNode]
type CiliumNodeConverter struct{ cinfo cmtypes.ClusterInfo }

func newCiliumNodeConverter(cinfo cmtypes.ClusterInfo) Converter[*cilium_api_v2.CiliumNode] {
	return &CiliumNodeConverter{cinfo: cinfo}
}

func (nc *CiliumNodeConverter) Convert(event resource.Event[*cilium_api_v2.CiliumNode]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
	if event.Kind == resource.Delete {
		node := nodeTypes.Node{Cluster: nc.cinfo.Name, Name: event.Key.Name}
		return noneIter[store.Key], singleIter[store.NamedKey](&node)
	}

	node := nodeTypes.ParseCiliumNode(event.Object)
	node.Cluster = nc.cinfo.Name
	node.ClusterID = nc.cinfo.ID
	return singleIter[store.Key](&node), noneIter[store.NamedKey]
}

// ----- CiliumIdentities ----- //

func newCiliumIdentityOptions() Options[*cilium_api_v2.CiliumIdentity] {
	return Options[*cilium_api_v2.CiliumIdentity]{
		Enabled:    true,
		Resource:   "CiliumIdentity",
		Prefix:     path.Join(identityCache.IdentitiesPath, "id"),
		StoreOpts:  []store.WSSOpt{store.WSSWithSyncedKeyOverride(identityCache.IdentitiesPath)},
		Namespaced: true,
	}
}

// CiliumIdentityConverter implements Converter[*cilium_api_v2.CiliumIdentity]
type CiliumIdentityConverter struct{ logger *slog.Logger }

func newCiliumIdentityConverter(logger *slog.Logger) Converter[*cilium_api_v2.CiliumIdentity] {
	return &CiliumIdentityConverter{logger: logger}
}

func (ic *CiliumIdentityConverter) Convert(event resource.Event[*cilium_api_v2.CiliumIdentity]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
	if event.Kind == resource.Delete {
		key := store.NewKVPair(event.Key.Name, "")
		return noneIter[store.Key], singleIter[store.NamedKey](key)
	}

	identity := event.Object
	if len(identity.SecurityLabels) == 0 {
		ic.logger.Warn(
			"Ignoring invalid identity",
			logfields.Error, errors.New("missing security labels"),
			logfields.Identity, identity.Name,
		)

		return noneIter[store.Key], noneIter[store.NamedKey]
	}

	lbls := labels.Map2Labels(identity.SecurityLabels, "").SortedList()
	kv := store.NewKVPair(identity.Name, string(lbls))
	return singleIter[store.Key](kv), noneIter[store.NamedKey]
}

// ----- CiliumEndpoints - CiliumEndpointSlices ----- //

func newCiliumEndpointOptions(cfg cmk8s.CiliumEndpointSliceConfig) Options[*types.CiliumEndpoint] {
	return Options[*types.CiliumEndpoint]{
		Enabled:    !cfg.EnableCiliumEndpointSlice,
		Resource:   "CiliumEndpoint",
		Prefix:     path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace),
		StoreOpts:  []store.WSSOpt{store.WSSWithSyncedKeyOverride(ipcache.IPIdentitiesPath)},
		Namespaced: true,
	}
}

func newCiliumEndpointConverter(logger *slog.Logger, cinfo cmtypes.ClusterInfo) Converter[*types.CiliumEndpoint] {
	return NewCachedCoverter(ciliumEndpointMapper)
}

func ciliumEndpointMapper(endpoint *types.CiliumEndpoint) iter.Seq[store.Key] {
	return func(yield func(store.Key) bool) {
		if n := endpoint.Networking; n != nil {
			for _, address := range n.Addressing {
				for _, ip := range []string{address.IPV4, address.IPV6} {
					if ip == "" {
						continue
					}
					entry := identity.IPIdentityPair{
						IP:                net.ParseIP(ip),
						HostIP:            net.ParseIP(n.NodeIP),
						K8sNamespace:      endpoint.Namespace,
						K8sPodName:        endpoint.Name,
						K8sServiceAccount: endpoint.ServiceAccount,
					}

					if endpoint.Identity != nil {
						entry.ID = identity.NumericIdentity(endpoint.Identity.ID)
					}

					if endpoint.Encryption != nil {
						entry.Key = uint8(endpoint.Encryption.Key)
					}

					if !yield(&entry) {
						return
					}
				}
			}
		}
	}
}

func newCiliumEndpointSliceOptions(cfg cmk8s.CiliumEndpointSliceConfig) Options[*cilium_api_v2a1.CiliumEndpointSlice] {
	return Options[*cilium_api_v2a1.CiliumEndpointSlice]{
		Enabled:    cfg.EnableCiliumEndpointSlice,
		Resource:   "CiliumEndpointSlice",
		Prefix:     path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace),
		StoreOpts:  []store.WSSOpt{store.WSSWithSyncedKeyOverride(ipcache.IPIdentitiesPath)},
		Namespaced: true,
	}
}

func newCiliumEndpointSliceConverter(logger *slog.Logger, cinfo cmtypes.ClusterInfo) Converter[*cilium_api_v2a1.CiliumEndpointSlice] {
	return NewCachedCoverter(ciliumEndpointSliceMapper)
}

func ciliumEndpointSliceMapper(endpointslice *cilium_api_v2a1.CiliumEndpointSlice) iter.Seq[store.Key] {
	return func(yield func(store.Key) bool) {
		for _, endpoint := range endpointslice.Endpoints {
			if n := endpoint.Networking; n != nil {
				for _, address := range n.Addressing {
					for _, ip := range []string{address.IPV4, address.IPV6} {
						if ip == "" {
							continue
						}

						entry := identity.IPIdentityPair{
							IP:                net.ParseIP(ip),
							HostIP:            net.ParseIP(n.NodeIP),
							K8sNamespace:      endpointslice.Namespace,
							K8sPodName:        endpoint.Name,
							ID:                identity.NumericIdentity(endpoint.IdentityID),
							Key:               uint8(endpoint.Encryption.Key),
							K8sServiceAccount: endpoint.ServiceAccount,
						}

						if !yield(&entry) {
							return
						}
					}
				}
			}
		}
	}
}
