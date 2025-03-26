// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"net"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupNodeMapV2TestSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestNodeMapV2(t *testing.T) {
	setupNodeMapV2TestSuite(t)
	logger := hivetest.Logger(t)
	nodeMap := newMapV2(logger, "test_cilium_node_map_v2", "test_cilium_node_map", Config{
		NodeMapMax: 1024,
	})
	err := nodeMap.init()
	require.NoError(t, err)
	defer nodeMap.bpfMap.Unpin()

	bpfNodeIDMap := map[uint16]string{}
	bpfNodeSPI := []uint8{}
	toMap := func(key *NodeKey, val *NodeValueV2) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		bpfNodeIDMap[val.NodeID] = address
		bpfNodeSPI = append(bpfNodeSPI, uint8(val.SPI))
	}

	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Empty(t, bpfNodeIDMap)
	require.Empty(t, bpfNodeSPI)

	err = nodeMap.Update(net.ParseIP("10.1.0.0"), 10, 3)
	require.NoError(t, err)
	err = nodeMap.Update(net.ParseIP("10.1.0.1"), 20, 3)
	require.NoError(t, err)

	bpfNodeIDMap = map[uint16]string{}
	bpfNodeSPI = []uint8{}
	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Len(t, bpfNodeIDMap, 2)
	require.Len(t, bpfNodeSPI, 2)

	err = nodeMap.Delete(net.ParseIP("10.1.0.0"))
	require.NoError(t, err)

	bpfNodeIDMap = map[uint16]string{}
	bpfNodeSPI = []uint8{}
	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Len(t, bpfNodeIDMap, 1)
	require.Len(t, bpfNodeSPI, 1)

	// ensure we see mirrored writes in MapV1
	_, err = ciliumebpf.LoadPinnedMap(bpf.MapPath(logger, "test_cilium_node_map"), nil)
	require.NoError(t, err)

	toMapV1 := func(key *NodeKey, val *NodeValue) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		require.Equal(t, address, bpfNodeIDMap[val.NodeID])
	}

	err = nodeMap.v1Map.IterateWithCallback(toMapV1)
	require.NoError(t, err)
}

func TestNodeMapMigration(t *testing.T) {
	setupNodeMapV2TestSuite(t)
	name1 := "test_cilium_node_map"
	name2 := "test_cilium_node_map_v2"
	emName := "test_cilium_encrypt_state"

	IP1 := net.ParseIP("10.1.0.0")
	IP2 := net.ParseIP("10.1.0.1")

	var ID1 uint16 = 10
	var ID2 uint16 = 20

	logger := hivetest.Logger(t)
	nodeMapV1 := newMap(logger, name1, Config{
		NodeMapMax: 1024,
	})
	err := nodeMapV1.init()
	require.NoError(t, err)

	nodeMapV2 := newMapV2(logger, name2, name1, Config{
		NodeMapMax: 1024,
	})
	err = nodeMapV2.init()
	require.NoError(t, err)
	defer nodeMapV2.bpfMap.Unpin()

	encryptMap := encrypt.NewMap(emName)
	err = encryptMap.OpenOrCreate()
	require.NoError(t, err)

	encrypt.MapUpdateContextWithMap(encryptMap, 0, 3)

	err = nodeMapV1.Update(IP1, ID1)
	require.NoError(t, err)
	err = nodeMapV1.Update(IP2, ID2)
	require.NoError(t, err)

	// done with nodeMapV2 so we can close the FD.
	nodeMapV2.close()

	// do migration
	err = nodeMapV2.migrateV1(name1, emName)
	require.NoError(t, err)

	// confirm we see the correct migrated values
	parse := func(k *NodeKey, v *NodeValueV2) {
		// family must be IPv4
		if k.Family != bpf.EndpointKeyIPv4 {
			t.Fatalf("want: %v, got: %v", bpf.EndpointKeyIPv4, k.Family)
		}
		ipv4 := net.IP(k.IP[:4])

		// IP must equal one of our two test IPs
		if !ipv4.Equal(IP1) && !ipv4.Equal(IP2) {
			t.Fatalf("migrated NodeValue2 did not match any IP under test: %v", ipv4)
		}

		// SPI must equal 3
		if v.SPI != 3 {
			t.Fatalf("wanted: 3, got: %v", v.SPI)
		}
	}
	MapV2(nodeMapV2).IterateWithCallback(parse)

	// confirm that the map is not removed, we need it around to mirror writes
	m, err := ciliumebpf.LoadPinnedMap(bpf.MapPath(logger, name1), nil)
	require.NoError(t, err)
	require.NotNil(t, m)
}
