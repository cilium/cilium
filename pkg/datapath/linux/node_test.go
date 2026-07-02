// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/config"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/kpr"
	subnetmap "github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

var (
	fakeNodeAddressing = fakenode.NewAddressing()

	nodeConfig = config.Config{
		NodeIPv4:            ip.AddrFromIP(fakeNodeAddressing.IPv4().PrimaryExternal()),
		NodeIPv6:            ip.AddrFromIP(fakeNodeAddressing.IPv6().PrimaryExternal()),
		CiliumInternalIPv4:  ip.AddrFromIP(fakeNodeAddressing.IPv4().Router()),
		CiliumInternalIPv6:  ip.AddrFromIP(fakeNodeAddressing.IPv6().Router()),
		DeviceMTU:           calcMtu.DeviceMTU,
		RouteMTU:            calcMtu.RouteMTU,
		RoutePostEncryptMTU: calcMtu.RoutePostEncryptMTU,
	}
	mtuConfig = mtu.NewConfiguration(0, false, false, false, false)
	calcMtu   = mtuConfig.Calculate(100)
	nh        = linuxNodeHandler{
		nodeConfig: nodeConfig,
		datapathConfig: DatapathConfiguration{
			HostDevice: "host_device",
		},
	}
	cr1 = netip.MustParsePrefix("10.1.0.0/16")
)

func TestCreateNodeRoute(t *testing.T) {
	dpConfig := DatapathConfiguration{
		HostDevice: "host_device",
	}
	log := hivetest.Logger(t)

	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	nodeHandler := newNodeHandler(log, dpConfig, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, nil, nil)
	nodeHandler.NodeConfigurationChanged(nodeConfig)

	c1 := netip.MustParsePrefix("10.10.0.0/16")
	generatedRoute, err := nodeHandler.createNodeRouteSpec(c1, false)
	require.NoError(t, err)
	require.Equal(t, *netipx.PrefixIPNet(c1), generatedRoute.Prefix)
	require.Equal(t, dpConfig.HostDevice, generatedRoute.Device)
	require.Equal(t, fakeNodeAddressing.IPv4().Router().To4(), generatedRoute.Nexthop.To4())
	require.Equal(t, fakeNodeAddressing.IPv4().Router().To4(), generatedRoute.Local.To4())

	c1 = netip.MustParsePrefix("beef:beef::/48")
	generatedRoute, err = nodeHandler.createNodeRouteSpec(c1, false)
	require.NoError(t, err)
	require.Equal(t, *netipx.PrefixIPNet(c1), generatedRoute.Prefix)
	require.Equal(t, dpConfig.HostDevice, generatedRoute.Device)
	require.Nil(t, generatedRoute.Nexthop)
	require.Equal(t, fakeNodeAddressing.IPv6().Router().To16(), generatedRoute.Local.To16())
}

func TestCreateNodeRouteSpecMtu(t *testing.T) {
	generatedRoute, err := nh.createNodeRouteSpec(cr1, false)

	require.NoError(t, err)
	require.NotEqual(t, 0, generatedRoute.MTU)

	generatedRoute, err = nh.createNodeRouteSpec(cr1, true)

	require.NoError(t, err)
	require.Equal(t, 0, generatedRoute.MTU)
}

func TestPrivilegedLocalRule(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	test := func(t *testing.T) {
		require.NoError(t, NodeEnsureLocalRoutingRule())

		// Expect at least one rule in the netns, with the first entry at pref 100
		// pointing at table 255.
		rules, err := route.ListRules(netlink.FAMILY_V4, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, linux_defaults.RulePriorityLocalLookup, rules[0].Priority)
		assert.Equal(t, unix.RT_TABLE_LOCAL, rules[0].Table)

		rules, err = route.ListRules(netlink.FAMILY_V6, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, linux_defaults.RulePriorityLocalLookup, rules[0].Priority)
		assert.Equal(t, unix.RT_TABLE_LOCAL, rules[0].Table)
	}

	ns.Do(func() error {
		// Install rules the first time.
		test(t)

		// Ensure idempotency.
		test(t)

		return nil
	})
}

// setupSubnetTable creates a statedb with a subnet table and inserts the given entries.
func setupSubnetTable(t *testing.T, entries []subnetmap.SubnetTableEntry) (*statedb.DB, statedb.RWTable[subnetmap.SubnetTableEntry]) {
	t.Helper()
	db := statedb.New()
	table, err := statedb.NewTable(db, subnetmap.TableName, subnetmap.SubnetPrimaryIndex, subnetmap.SubnetLPMIndex)
	require.NoError(t, err)

	wtx := db.WriteTxn(table)
	for _, e := range entries {
		_, _, err := table.Insert(wtx, e)
		require.NoError(t, err)
	}
	wtx.Commit()

	return db, table
}

func makeNode(ipv4 string) *nodeTypes.Node {
	return &nodeTypes.Node{
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP(ipv4)},
		},
	}
}

func makeNodeWithPodCIDRs(ipv4 string, podCIDRs ...string) *nodeTypes.Node {
	n := makeNode(ipv4)
	for _, c := range podCIDRs {
		n.IPv4AllocCIDR = cidr.MustParseCIDR(c)
	}
	return n
}

func TestHybridMode(t *testing.T) {
	tests := []struct {
		name                  string
		enableEncapsulation   bool
		requiresNativeRouting bool
		expected              bool
	}{
		{
			name:                  "hybrid mode - both enabled",
			enableEncapsulation:   true,
			requiresNativeRouting: true,
			expected:              true,
		},
		{
			name:                  "tunnel only - not hybrid",
			enableEncapsulation:   true,
			requiresNativeRouting: false,
			expected:              false,
		},
		{
			name:                  "native only - not hybrid",
			enableEncapsulation:   false,
			requiresNativeRouting: true,
			expected:              false,
		},
		{
			name:                  "neither - not hybrid",
			enableEncapsulation:   false,
			requiresNativeRouting: false,
			expected:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &linuxNodeHandler{
				nodeConfig: config.Config{
					EnableEncapsulation:   tt.enableEncapsulation,
					RequiresNativeRouting: tt.requiresNativeRouting,
				},
			}
			assert.Equal(t, tt.expected, handler.hybridMode())
		})
	}
}

func TestLookupSubnetID(t *testing.T) {
	tests := []struct {
		name     string
		entries  []subnetmap.SubnetTableEntry
		addr     netip.Addr
		expected uint32
	}{
		{
			name: "exact match",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
			},
			addr:     netip.MustParseAddr("10.0.0.5"),
			expected: 1,
		},
		{
			name: "no match returns 0",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
			},
			addr:     netip.MustParseAddr("192.168.1.5"),
			expected: 0,
		},
		{
			name:     "empty table returns 0",
			entries:  []subnetmap.SubnetTableEntry{},
			addr:     netip.MustParseAddr("10.0.0.5"),
			expected: 0,
		},
		{
			name: "LPM - broader prefix matches",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/16"), 2),
			},
			addr:     netip.MustParseAddr("10.0.5.10"),
			expected: 2,
		},
		{
			name:     "nil db and table returns 0",
			entries:  nil, // signals nil db/table
			addr:     netip.MustParseAddr("10.0.0.5"),
			expected: 0,
		},
		{
			name: "pod IP not in admin-configured node CIDRs - no match",
			entries: []subnetmap.SubnetTableEntry{
				// Admin configures node CIDRs only; pod CIDRs are inserted
				// separately by insertPodCIDRSubnetEntries at node join time.
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
			},
			addr:     netip.MustParseAddr("10.244.1.5"),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handler *linuxNodeHandler
			if tt.entries == nil {
				handler = &linuxNodeHandler{}
			} else {
				db, table := setupSubnetTable(t, tt.entries)
				handler = &linuxNodeHandler{db: db, subnetTable: table}
			}
			assert.Equal(t, tt.expected, handler.lookupSubnetID(tt.addr))
		})
	}
}

func TestNodeRequiresTunnelRoute(t *testing.T) {
	tests := []struct {
		name         string
		localPodCIDR string
		remoteNode   *nodeTypes.Node
		entries      []subnetmap.SubnetTableEntry
		expected     bool
	}{
		{
			name:         "same subnet group - no tunnel needed",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNodeWithPodCIDRs("10.0.0.10", "10.244.1.0/24"),
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			expected: false,
		},
		{
			name:         "different subnet groups - tunnel needed",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNodeWithPodCIDRs("10.1.0.10", "10.245.0.0/24"),
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.245.0.0/16"), 2),
			},
			expected: true,
		},
		{
			name:         "broad CIDR covers both pod CIDRs - same group",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNodeWithPodCIDRs("10.0.1.10", "10.244.1.0/24"),
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			expected: false,
		},
		{
			name:         "nil remote node - tunnel needed",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   nil,
			entries:      []subnetmap.SubnetTableEntry{},
			expected:     true,
		},
		{
			name:         "remote node with no pod CIDRs - tunnel needed",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNode("10.0.0.10"),
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			expected: true,
		},
		{
			name:         "empty subnet table - tunnel needed (no local groups)",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNodeWithPodCIDRs("10.0.0.10", "10.244.1.0/24"),
			entries:      []subnetmap.SubnetTableEntry{},
			expected:     true,
		},
		{
			name:         "local pod CIDR in group but remote not - tunnel needed",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNodeWithPodCIDRs("192.168.1.10", "10.99.0.0/24"),
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			expected: true,
		},
		{
			name:         "multiple groups - pod CIDRs in separate groups",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNodeWithPodCIDRs("10.20.0.10", "10.246.0.0/24"),
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.245.0.0/16"), 1),
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.246.0.0/16"), 2),
			},
			expected: true,
		},
		{
			name:         "multiple groups - pod CIDRs in same group via different parent CIDRs",
			localPodCIDR: "10.244.0.0/24",
			remoteNode:   makeNodeWithPodCIDRs("10.10.0.10", "10.245.0.0/24"),
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.245.0.0/16"), 1),
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.246.0.0/16"), 2),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := hivetest.Logger(t)
			db, table := setupSubnetTable(t, tt.entries)

			localNode := node.LocalNode{
				Node: nodeTypes.Node{
					IPAddresses: []nodeTypes.Address{
						{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.5")},
					},
				},
			}
			if tt.localPodCIDR != "" {
				localNode.Node.IPv4AllocCIDR = cidr.MustParseCIDR(tt.localPodCIDR)
			}
			lns := node.NewTestLocalNodeStore(localNode)

			handler := newNodeHandler(log, DatapathConfiguration{}, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, db, table)

			result := handler.nodeRequiresTunnelRoute(tt.remoteNode)
			assert.Equal(t, tt.expected, result, "nodeRequiresTunnelRoute returned unexpected value")
		})
	}
}

func TestInsertPodCIDRSubnetEntries(t *testing.T) {
	tests := []struct {
		name            string
		entries         []subnetmap.SubnetTableEntry
		node            *nodeTypes.Node
		expectedEntries []netip.Prefix
		expectedGroupID uint32
	}{
		{
			name: "inserts pod CIDR with correct group ID",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			node:            makeNodeWithPodCIDRs("10.0.0.5", "10.244.1.0/24"),
			expectedEntries: []netip.Prefix{netip.MustParsePrefix("10.244.1.0/24")},
			expectedGroupID: 1,
		},
		{
			name: "pod CIDR not in any group - not inserted",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			node:            makeNodeWithPodCIDRs("10.0.0.5", "10.99.0.0/24"),
			expectedEntries: nil,
		},
		{
			name: "node with no pod CIDRs - nothing inserted",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			node:            makeNode("10.0.0.5"),
			expectedEntries: nil,
		},
		{
			name:            "nil db and table - no panic",
			entries:         nil,
			node:            makeNodeWithPodCIDRs("10.0.0.5", "10.244.1.0/24"),
			expectedEntries: nil,
		},
		{
			name: "node with no IP but pod CIDR in group - pod CIDR still inserted",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.0.0/16"), 1),
			},
			node: &nodeTypes.Node{
				IPv4AllocCIDR: cidr.MustParseCIDR("10.244.1.0/24"),
			},
			expectedEntries: []netip.Prefix{netip.MustParsePrefix("10.244.1.0/24")},
			expectedGroupID: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handler *linuxNodeHandler
			if tt.entries == nil {
				handler = &linuxNodeHandler{}
			} else {
				db, table := setupSubnetTable(t, tt.entries)
				handler = &linuxNodeHandler{db: db, subnetTable: table}
			}

			handler.insertPodCIDRSubnetEntries(tt.node)

			if tt.expectedEntries == nil {
				if handler.db == nil {
					return
				}
				// Verify no new entries were added beyond the originals
				txn := handler.db.ReadTxn()
				count := 0
				for range handler.subnetTable.All(txn) {
					count++
				}
				assert.Equal(t, len(tt.entries), count, "no new entries should be added")
				return
			}

			txn := handler.db.ReadTxn()
			for _, prefix := range tt.expectedEntries {
				addr := prefix.Addr()
				entry, _, found := handler.subnetTable.Get(txn, subnetmap.SubnetLPMIndex.Query(addr))
				assert.True(t, found, "expected entry for %s", prefix)
				if found {
					assert.Equal(t, tt.expectedGroupID, entry.Value, "group ID mismatch for %s", prefix)
				}
			}
		})
	}
}

func TestDeletePodCIDRSubnetEntries(t *testing.T) {
	tests := []struct {
		name           string
		entries        []subnetmap.SubnetTableEntry
		node           *nodeTypes.Node
		remainingCount int
	}{
		{
			name: "deletes pod CIDR entry",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.244.1.0/24"), 1),
			},
			node:           makeNodeWithPodCIDRs("10.0.0.5", "10.244.1.0/24"),
			remainingCount: 1, // only the node CIDR remains
		},
		{
			name: "delete non-existent entry - no error",
			entries: []subnetmap.SubnetTableEntry{
				subnetmap.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
			},
			node:           makeNodeWithPodCIDRs("10.0.0.5", "10.244.1.0/24"),
			remainingCount: 1, // original entry untouched
		},
		{
			name:           "nil db and table - no panic",
			entries:        nil,
			node:           makeNodeWithPodCIDRs("10.0.0.5", "10.244.1.0/24"),
			remainingCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handler *linuxNodeHandler
			if tt.entries == nil {
				handler = &linuxNodeHandler{}
				handler.deletePodCIDRSubnetEntries(tt.node)
				return // no panic = pass
			}

			db, table := setupSubnetTable(t, tt.entries)
			handler = &linuxNodeHandler{db: db, subnetTable: table}

			handler.deletePodCIDRSubnetEntries(tt.node)

			txn := handler.db.ReadTxn()
			count := 0
			for range handler.subnetTable.All(txn) {
				count++
			}
			assert.Equal(t, tt.remainingCount, count)
		})
	}
}
