// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testipcache

import (
	"context"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
)

type MockIPCache struct{}

func (m *MockIPCache) GetNamedPorts() types.NamedPortMultiMap {
	return nil
}

func (m *MockIPCache) AddListener(listener ipcache.IPIdentityMappingListener) {}

func (m *MockIPCache) LookupByIP(IP string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (m *MockIPCache) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (namedPortsChanged bool, err error) {
	return false, nil
}

func (m *MockIPCache) Delete(IP string, source source.Source) (namedPortsChanged bool) {
	return false
}

func (m *MockIPCache) RemoveLabelsExcluded(lbls labels.Labels, toExclude map[netip.Prefix]struct{}, resource ipcacheTypes.ResourceID) {
}

func (m *MockIPCache) DeleteOnMetadataMatch(IP string, source source.Source, namespace, name string) (namedPortsChanged bool) {
	return false
}

func (m *MockIPCache) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	return 0
}

func (m *MockIPCache) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	return 0
}

func (m *MockIPCache) WaitForRevision(ctx context.Context, rev uint64) error {
	return nil
}

func NewMockIPCache() *MockIPCache {
	return &MockIPCache{}
}
