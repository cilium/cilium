// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache/types"
	store2 "github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	types2 "github.com/cilium/cilium/pkg/types"
)

type Interface interface {
	Shutdown() error
	Lock()
	Unlock()
	RLock()
	RUnlock()
	AddListener(listener IPIdentityMappingListener)
	UpdateController(
		name string,
		params controller.ControllerParams,
	)
	GetHostIPCache(ip string) (net.IP, uint8)
	GetK8sMetadata(ip netip.Addr) *K8sMetadata
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (namedPortsChanged bool, err error)
	DumpToListener(listener IPIdentityMappingListener)
	UpsertMetadata(prefix netip.Prefix, src source.Source, resource types.ResourceID, aux ...IPMetadata)
	UpsertMetadataBatch(updates ...MU) (revision uint64)
	RemoveMetadata(prefix netip.Prefix, resource types.ResourceID, aux ...IPMetadata)
	RemoveMetadataBatch(updates ...MU) (revision uint64)
	UpsertPrefixes(prefixes []netip.Prefix, src source.Source, resource types.ResourceID) (revision uint64)
	RemovePrefixes(prefixes []netip.Prefix, src source.Source, resource types.ResourceID)
	UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, resource types.ResourceID)
	RemoveLabels(cidr netip.Prefix, lbls labels.Labels, resource types.ResourceID)
	OverrideIdentity(prefix netip.Prefix, identityLabels labels.Labels, src source.Source, resource types.ResourceID)
	RemoveIdentityOverride(cidr netip.Prefix, identityLabels labels.Labels, resource types.ResourceID)
	WaitForRevision(desired uint64)
	DumpToListenerLocked(listener IPIdentityMappingListener)
	GetNamedPorts() (npm types2.NamedPortMultiMap)
	DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool)
	Delete(IP string, source source.Source) (namedPortsChanged bool)
	LookupByIP(IP string) (Identity, bool)
	LookupByIPRLocked(IP string) (Identity, bool)
	LookupByPrefixRLocked(prefix string) (identity Identity, exists bool)
	LookupByPrefix(IP string) (Identity, bool)
	LookupSecIDByIP(ip netip.Addr) (id Identity, ok bool)
	LookupByIdentity(id identity.NumericIdentity) (ips []string)
	LookupByHostRLocked(hostIPv4, hostIPv6 net.IP) (cidrs []net.IPNet)
	AllocateCIDRs(
		prefixes []netip.Prefix, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity,
	) ([]*identity.Identity, error)
	ReleaseCIDRIdentitiesByCIDR(prefixes []netip.Prefix)
	GetMetadataLabelsByIP(addr netip.Addr) labels.Labels
	GetMetadataByPrefix(prefix netip.Prefix) PrefixInfo
	InjectLabels(ctx context.Context, modifiedPrefixes []netip.Prefix) (remainingPrefixes []netip.Prefix, err error)
	UpdatePolicyMaps(ctx context.Context, addedIdentities, deletedIdentities map[identity.NumericIdentity]labels.LabelArray)
	RemoveLabelsExcluded(
		lbls labels.Labels,
		toExclude map[netip.Prefix]struct{},
		rid types.ResourceID,
	)
	TriggerLabelInjection()
	InitIPIdentityWatcher(ctx context.Context, factory store2.Factory)

	WithholdLocalIdentities(nids []identity.NumericIdentity)
	UnwithholdLocalIdentities(nids []identity.NumericIdentity)
}
