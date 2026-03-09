// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	pkgipcache "github.com/cilium/cilium/pkg/ipcache"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

type mapRecorder struct {
	updates map[string]ipcacheMap.RemoteEndpointInfo
	deletes []string
}

func newMapRecorder() *mapRecorder {
	return &mapRecorder{updates: make(map[string]ipcacheMap.RemoteEndpointInfo)}
}

func (m *mapRecorder) Update(key bpf.MapKey, value bpf.MapValue) error {
	k := key.(*ipcacheMap.Key)
	v := value.(*ipcacheMap.RemoteEndpointInfo)
	m.updates[k.String()] = *v
	return nil
}

func (m *mapRecorder) Delete(key bpf.MapKey) error {
	k := key.(*ipcacheMap.Key)
	m.deletes = append(m.deletes, k.String())
	delete(m.updates, k.String())
	return nil
}

func TestBPFListenerBuffersFloatingTunnelEndpointMapWrites(t *testing.T) {
	logger := hivetest.Logger(t)
	oldFloating := option.Config.EnableFloatingTunnelEndpoint
	t.Cleanup(func() {
		option.Config.EnableFloatingTunnelEndpoint = oldFloating
	})
	option.Config.EnableFloatingTunnelEndpoint = true

	ipc := pkgipcache.NewIPCache(&pkgipcache.Configuration{
		Context:                      t.Context(),
		Logger:                       logger,
		EnableFloatingTunnelEndpoint: true,
	})
	lns := node.NewTestLocalNodeStore(node.LocalNode{
		Node: nodeTypes.Node{
			IPAddresses: []nodeTypes.Address{{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")}},
		},
		Local: &node.LocalNodeInfo{UnderlayProtocol: tunnel.IPv4},
	})
	recorder := newMapRecorder()
	listener := NewListener(recorder, nil, tunnel.Config{}, logger, lns)
	ipc.AddTunnelEndpointMappingListener(listener)

	cidrCluster := cmtypes.MustParsePrefixCluster("10.1.0.10/32")
	hostIP := net.ParseIP("10.0.1.2")
	mappedIP := net.ParseIP("192.0.2.2")

	listener.OnIPIdentityCacheChange(
		pkgipcache.Upsert,
		cidrCluster,
		nil,
		hostIP,
		nil,
		pkgipcache.Identity{ID: 1234, Source: source.CustomResource},
		7,
		nil,
		0,
	)
	require.Empty(t, recorder.updates)

	ipc.UpsertTunnelEndpointMapping(hostIP, mappedIP)
	key := ipcacheMap.NewKey(cidrCluster.AsPrefix(), uint16(cidrCluster.ClusterID())).String()
	value, ok := recorder.updates[key]
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("192.0.2.2"), value.GetTunnelEndpoint())
}

func TestBPFListenerRemovesMappedEntryWhenTunnelMappingDisappears(t *testing.T) {
	logger := hivetest.Logger(t)
	oldFloating := option.Config.EnableFloatingTunnelEndpoint
	t.Cleanup(func() {
		option.Config.EnableFloatingTunnelEndpoint = oldFloating
	})
	option.Config.EnableFloatingTunnelEndpoint = true

	ipc := pkgipcache.NewIPCache(&pkgipcache.Configuration{
		Context:                      t.Context(),
		Logger:                       logger,
		EnableFloatingTunnelEndpoint: true,
	})
	lns := node.NewTestLocalNodeStore(node.LocalNode{
		Node: nodeTypes.Node{
			IPAddresses: []nodeTypes.Address{{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")}},
		},
		Local: &node.LocalNodeInfo{UnderlayProtocol: tunnel.IPv4},
	})
	recorder := newMapRecorder()
	listener := NewListener(recorder, nil, tunnel.Config{}, logger, lns)
	ipc.AddTunnelEndpointMappingListener(listener)

	cidrCluster := cmtypes.MustParsePrefixCluster("10.1.0.10/32")
	hostIP := net.ParseIP("10.0.1.2")
	mappedIP := net.ParseIP("192.0.2.2")
	key := ipcacheMap.NewKey(cidrCluster.AsPrefix(), uint16(cidrCluster.ClusterID())).String()

	ipc.UpsertTunnelEndpointMapping(hostIP, mappedIP)
	listener.OnIPIdentityCacheChange(
		pkgipcache.Upsert,
		cidrCluster,
		nil,
		hostIP,
		nil,
		pkgipcache.Identity{ID: 1234, Source: source.CustomResource},
		7,
		nil,
		0,
	)
	require.Contains(t, recorder.updates, key)

	ipc.DeleteTunnelEndpointMapping(hostIP)
	require.NotContains(t, recorder.updates, key)
	require.Contains(t, recorder.deletes, key)
}
