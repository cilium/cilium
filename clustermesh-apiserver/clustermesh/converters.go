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

var _ Converter[*cilium_api_v2.CiliumNode] = (*NodeConverter)(nil)
var _ Converter[*cilium_api_v2.CiliumIdentity] = (*IdentityConverter)(nil)
var _ Converter[*types.CiliumEndpoint] = (*EndpointConverter)(nil)
var _ Converter[*cilium_api_v2a1.CiliumEndpointSlice] = (*EndpointSliceConverter)(nil)

// ----- CiliumNodes ----- //

func newNodeOptions() Options[*cilium_api_v2.CiliumNode] {
	return Options[*cilium_api_v2.CiliumNode]{
		Enabled:  true,
		Resource: "CiliumNode",
		Prefix:   nodeStore.NodeStorePrefix,
	}
}

// NodeConverter implements Converter[*cilium_api_v2.CiliumNode]
type NodeConverter struct{ cinfo cmtypes.ClusterInfo }

func newNodeConverter(cinfo cmtypes.ClusterInfo) Converter[*cilium_api_v2.CiliumNode] {
	return &NodeConverter{cinfo: cinfo}
}

func (nc *NodeConverter) Convert(event resource.Event[*cilium_api_v2.CiliumNode]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
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

func newIdentityOptions() Options[*cilium_api_v2.CiliumIdentity] {
	return Options[*cilium_api_v2.CiliumIdentity]{
		Enabled:   true,
		Resource:  "CiliumIdentity",
		Prefix:    path.Join(identityCache.IdentitiesPath, "id"),
		StoreOpts: []store.WSSOpt{store.WSSWithSyncedKeyOverride(identityCache.IdentitiesPath)},
	}
}

// IdentityConverter implements Converter[*cilium_api_v2.CiliumIdentity]
type IdentityConverter struct{ logger *slog.Logger }

func newIdentityConverter(logger *slog.Logger) Converter[*cilium_api_v2.CiliumIdentity] {
	return &IdentityConverter{logger: logger}
}

func (ic *IdentityConverter) Convert(event resource.Event[*cilium_api_v2.CiliumIdentity]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
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

func newEndpointOptions(cfg cmk8s.CiliumEndpointSliceConfig) Options[*types.CiliumEndpoint] {
	return Options[*types.CiliumEndpoint]{
		Enabled:   !cfg.EnableCiliumEndpointSlice,
		Resource:  "CiliumEndpoint",
		Prefix:    path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace),
		StoreOpts: []store.WSSOpt{store.WSSWithSyncedKeyOverride(ipcache.IPIdentitiesPath)},
	}
}

// EndpointConverter implements Converter[*types.CiliumEndpoint]
type EndpointConverter struct {
	endpointConverterCommon[*types.CiliumEndpoint]
}

func newEndpointConverter(logger *slog.Logger, cinfo cmtypes.ClusterInfo) Converter[*types.CiliumEndpoint] {
	return &endpointConverterCommon[*types.CiliumEndpoint]{
		cache: make(map[string]sets.Set[string]),
		iter:  (&EndpointConverter{}).all,
	}
}

func newEndpointSliceOptions(cfg cmk8s.CiliumEndpointSliceConfig) Options[*cilium_api_v2a1.CiliumEndpointSlice] {
	return Options[*cilium_api_v2a1.CiliumEndpointSlice]{
		Enabled:   cfg.EnableCiliumEndpointSlice,
		Resource:  "CiliumEndpointSlice",
		Prefix:    path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace),
		StoreOpts: []store.WSSOpt{store.WSSWithSyncedKeyOverride(ipcache.IPIdentitiesPath)},
	}
}

// EndpointSliceConverter implements Converter[*cilium_api_v2a1.CiliumEndpointSlice]
type EndpointSliceConverter struct {
	endpointConverterCommon[*cilium_api_v2a1.CiliumEndpointSlice]
}

type endpointConverterCommon[T interface {
	runtime.Object
	*types.CiliumEndpoint | *cilium_api_v2a1.CiliumEndpointSlice
}] struct {
	iter  func(T) iter.Seq2[string, identity.IPIdentityPair]
	cache map[string]sets.Set[string]
}

func newEndpointSliceConverter(logger *slog.Logger, cinfo cmtypes.ClusterInfo) Converter[*cilium_api_v2a1.CiliumEndpointSlice] {
	return &endpointConverterCommon[*cilium_api_v2a1.CiliumEndpointSlice]{
		cache: make(map[string]sets.Set[string]),
		iter:  (&EndpointSliceConverter{}).all,
	}
}

func (ec *endpointConverterCommon[T]) Convert(event resource.Event[T]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
	nsname := event.Key.String()

	if event.Kind == resource.Delete {
		toDelete := maps.Keys(ec.cache[nsname])
		delete(ec.cache, nsname)
		return noneIter[store.Key], ec.deletesIter(toDelete)
	}

	var (
		toAdd    []store.Key
		toDelete = ec.cache[nsname]
		current  = sets.New[string]()
	)

	for ip, entry := range ec.iter(event.Object) {
		toAdd = append(toAdd, &entry)
		current.Insert(ip)
		toDelete.Delete(ip)
	}

	ec.cache[nsname] = current
	return slices.Values(toAdd), ec.deletesIter(maps.Keys(toDelete))
}

func (ec *endpointConverterCommon[T]) deletesIter(ips iter.Seq[string]) iter.Seq[store.NamedKey] {
	return func(yield func(store.NamedKey) bool) {
		for ip := range ips {
			if !yield(&identity.IPIdentityPair{IP: net.ParseIP(ip)}) {
				return
			}
		}
	}
}

func (ec *EndpointConverter) all(endpoint *types.CiliumEndpoint) iter.Seq2[string, identity.IPIdentityPair] {
	return func(yield func(string, identity.IPIdentityPair) bool) {
		if n := endpoint.Networking; n != nil {
			for _, address := range n.Addressing {
				for _, ip := range []string{address.IPV4, address.IPV6} {
					if ip == "" {
						continue
					}
					entry := identity.IPIdentityPair{
						IP:           net.ParseIP(ip),
						HostIP:       net.ParseIP(n.NodeIP),
						K8sNamespace: endpoint.Namespace,
						K8sPodName:   endpoint.Name,
					}

					if endpoint.Identity != nil {
						entry.ID = identity.NumericIdentity(endpoint.Identity.ID)
					}

					if endpoint.Encryption != nil {
						entry.Key = uint8(endpoint.Encryption.Key)
					}

					if !yield(ip, entry) {
						return
					}
				}
			}
		}
	}
}

func (ec *EndpointSliceConverter) all(endpointslice *cilium_api_v2a1.CiliumEndpointSlice) iter.Seq2[string, identity.IPIdentityPair] {
	return func(yield func(string, identity.IPIdentityPair) bool) {
		for _, endpoint := range endpointslice.Endpoints {
			if n := endpoint.Networking; n != nil {
				for _, address := range n.Addressing {
					for _, ip := range []string{address.IPV4, address.IPV6} {
						if ip == "" {
							continue
						}

						entry := identity.IPIdentityPair{
							IP:           net.ParseIP(ip),
							HostIP:       net.ParseIP(n.NodeIP),
							K8sNamespace: endpointslice.Namespace,
							K8sPodName:   endpoint.Name,
							ID:           identity.NumericIdentity(endpoint.IdentityID),
							Key:          uint8(endpoint.Encryption.Key),
						}

						if !yield(ip, entry) {
							return
						}
					}
				}
			}
		}
	}
}
