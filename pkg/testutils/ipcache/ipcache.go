// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testipcache

import (
	"context"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
)

type MockIPCache struct{}

func (m *MockIPCache) WithholdLocalIdentities(nids []identity.NumericIdentity) {}

func (m *MockIPCache) UnwithholdLocalIdentities(nids []identity.NumericIdentity) {}

func (m *MockIPCache) Shutdown() error {
	return nil
}

func (m *MockIPCache) Lock() {}

func (m *MockIPCache) Unlock() {}

func (m *MockIPCache) RLock() {}

func (m *MockIPCache) RUnlock() {}

func (m *MockIPCache) UpdateController(name string, params controller.ControllerParams) {}

func (m *MockIPCache) GetHostIPCache(ip string) (net.IP, uint8) {
	return net.IP{}, 0
}

func (m *MockIPCache) GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata {
	return &ipcache.K8sMetadata{}
}

func (m *MockIPCache) DumpToListener(listener ipcache.IPIdentityMappingListener) {}

func (m *MockIPCache) UpsertMetadata(prefix netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
}

func (m *MockIPCache) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	return 0
}

func (m *MockIPCache) RemoveMetadata(prefix netip.Prefix, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
}

func (m *MockIPCache) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	return 0
}

func (m *MockIPCache) RemoveLabels(cidr netip.Prefix, lbls labels.Labels, resource ipcacheTypes.ResourceID) {
}

func (m *MockIPCache) OverrideIdentity(prefix netip.Prefix, identityLabels labels.Labels, src source.Source, resource ipcacheTypes.ResourceID) {
}

func (m *MockIPCache) RemoveIdentityOverride(cidr netip.Prefix, identityLabels labels.Labels, resource ipcacheTypes.ResourceID) {
}

func (m *MockIPCache) WaitForRevision(desired uint64) {}

func (m *MockIPCache) DumpToListenerLocked(listener ipcache.IPIdentityMappingListener) {}

func (m *MockIPCache) LookupByIPRLocked(IP string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (m *MockIPCache) LookupByPrefixRLocked(prefix string) (identity ipcache.Identity, exists bool) {
	return ipcache.Identity{}, false
}

func (m *MockIPCache) LookupByPrefix(IP string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (m *MockIPCache) LookupSecIDByIP(ip netip.Addr) (id ipcache.Identity, ok bool) {
	return ipcache.Identity{}, false
}

func (m *MockIPCache) LookupByIdentity(id identity.NumericIdentity) (ips []string) {
	return []string{}
}

func (m *MockIPCache) LookupByHostRLocked(hostIPv4, hostIPv6 net.IP) (cidrs []net.IPNet) {
	return []net.IPNet{}
}

func (m *MockIPCache) GetMetadataLabelsByIP(addr netip.Addr) labels.Labels {
	return labels.Labels{}
}

func (m *MockIPCache) GetMetadataByPrefix(prefix netip.Prefix) ipcache.PrefixInfo {
	return ipcache.PrefixInfo{}
}

func (m *MockIPCache) InjectLabels(ctx context.Context, modifiedPrefixes []netip.Prefix) (remainingPrefixes []netip.Prefix, err error) {
	return
}

func (m *MockIPCache) UpdatePolicyMaps(ctx context.Context, addedIdentities, deletedIdentities map[identity.NumericIdentity]labels.LabelArray) {
}

func (m *MockIPCache) TriggerLabelInjection() {}

func (m *MockIPCache) InitIPIdentityWatcher(ctx context.Context, factory store.Factory) {}

func (m *MockIPCache) GetNamedPorts() types.NamedPortMultiMap {
	return nil
}

func (m *MockIPCache) AddListener(listener ipcache.IPIdentityMappingListener) {}

func (m *MockIPCache) AllocateCIDRs(prefixes []netip.Prefix, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity) ([]*identity.Identity, error) {
	return nil, nil
}

func (m *MockIPCache) ReleaseCIDRIdentitiesByCIDR(prefixes []netip.Prefix) {}

func (m *MockIPCache) LookupByIP(IP string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (m *MockIPCache) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (namedPortsChanged bool, err error) {
	return false, nil
}

func (m *MockIPCache) Delete(IP string, source source.Source) (namedPortsChanged bool) {
	return false
}

func (m *MockIPCache) UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, resource ipcacheTypes.ResourceID) {
}

func (m *MockIPCache) RemoveLabelsExcluded(lbls labels.Labels, toExclude map[netip.Prefix]struct{}, resource ipcacheTypes.ResourceID) {
}

func (m *MockIPCache) DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool) {
	return false
}

func (m *MockIPCache) UpsertPrefixes(prefixes []netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID) uint64 {
	return 0
}

func (m *MockIPCache) RemovePrefixes(prefixes []netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID) {
}

func NewMockIPCache() *MockIPCache {
	return &MockIPCache{}
}
