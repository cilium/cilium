// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net"
	"net/netip"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
)

type mockListener struct{}

func (ml *mockListener) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, nodeID uint16, k8sMeta *ipcache.K8sMetadata) {
}
func (ml *mockListener) OnIPIdentityCacheGC()                   {}
func (ml *mockListener) GetOldNIDs() []identity.NumericIdentity { return nil }
func (ml *mockListener) GetOldCIDRs() []netip.Prefix            { return nil }
func (ml *mockListener) GetOldIngressIPs() []*net.IPNet         { return nil }

func NewMockListener() BPFListenerInterface {
	return &mockListener{}
}
