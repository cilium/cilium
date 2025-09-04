// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/u8proto"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

func TestCreatecreateGRPCClient(t *testing.T) {
	logger := slog.Default()

	client := createGRPCClient(logger, nil, nil, nil)

	require.NotNil(t, client)
}

func assertDNSRules(t *testing.T, c *GRPCClient, epID uint32, pp restore.PortProto, expServerIDs []uint32, expPatterns []string) {
	t.Helper()
	rtxn := c.db.ReadTxn()
	ck := DNSRulesCompositeKey(epID, pp)
	row, _, found := c.dnsRulesTable.Get(rtxn, DNSRulesIndex.Query(ck))
	require.True(t, found, "no DNSRules for ep=%d portProto=%v", epID, pp)

	var gotIDs []uint32
	var gotPatterns []string
	for k, v := range row.DNSRule {
		for _, id := range k.GetSelections(versioned.Latest()) {
			gotIDs = append(gotIDs, id.Uint32())
		}
		if v != nil {
			for _, r := range v.L7Rules.DNS {
				if r.MatchPattern != "" {
					gotPatterns = append(gotPatterns, r.MatchPattern)
				}
			}
		}
	}
	require.ElementsMatch(t, expServerIDs, gotIDs, "server IDs mismatch")
	require.ElementsMatch(t, expPatterns, gotPatterns, "patterns mismatch")
}

func TestUpdateDNSRules(t *testing.T) {
	db := statedb.New()
	table, err := newDNSRulesTable(db)
	require.NoError(t, err)

	logger := hivetest.Logger(t)
	c := &GRPCClient{
		logger:        logger,
		db:            db,
		dnsRulesTable: table,
	}

	pp53 := restore.MakeV2PortProto(53, u8proto.UDP)
	pp54 := restore.MakeV2PortProto(54, u8proto.TCP)

	tests := []struct {
		name   string
		input  []*pb.DNSPolicy
		checks []struct {
			epID      uint32
			pp        restore.PortProto
			serverIDs []uint32
			patterns  []string
		}
	}{
		{
			name: "single pattern single server",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 100,
					DnsPattern:       []string{"example.com"},
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:     53,
						DnsServerProto:    uint32(u8proto.UDP),
						DnsServerIdentity: 200,
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{100, pp53, []uint32{200}, []string{"example.com"}},
			},
		},
		{
			name: "multiple patterns single server",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 101,
					DnsPattern:       []string{"a.com", "b.com"},
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:     54,
						DnsServerProto:    uint32(u8proto.TCP),
						DnsServerIdentity: 210,
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{101, pp54, []uint32{210}, []string{"a.com", "b.com"}},
			},
		},
		{
			name: "multiple servers same policy",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 102,
					DnsPattern:       []string{"group.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 220},
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 221},
					},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{102, pp53, []uint32{220, 221}, []string{"group.com"}},
			},
		},
		{
			name: "multiple policies different servers",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 103,
					DnsPattern:       []string{"one.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 230},
					},
				},
				{
					SourceEndpointId: 103,
					DnsPattern:       []string{"two.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 231},
					},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{103, pp53, []uint32{230, 231}, []string{"one.com", "two.com"}},
			},
		},
		{
			name: "different ports same endpoint",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 104,
					DnsPattern:       []string{"p53.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 240},
					},
				},
				{
					SourceEndpointId: 104,
					DnsPattern:       []string{"p54.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 54, DnsServerProto: uint32(u8proto.TCP), DnsServerIdentity: 241},
					},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{104, pp53, []uint32{240}, []string{"p53.com"}},
				{104, pp54, []uint32{241}, []string{"p54.com"}},
			},
		},
		{
			name: "empty patterns single server (nil policy entry)",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 110,
					// DnsPattern omitted -> len==0 => nil policy value stored
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:     53,
						DnsServerProto:    uint32(u8proto.UDP),
						DnsServerIdentity: 2100,
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{110, pp53, []uint32{2100}, []string{}}, // expect no patterns
			},
		},
		{
			name: "No dns server identity",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 110,
					DnsPattern:       []string{"p53.com"},
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:  53,
						DnsServerProto: uint32(u8proto.UDP),
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{110, pp53, []uint32{0}, []string{"p53.com"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := c.updateDNSRules(tc.input)
			require.NoError(t, err)

			for _, chk := range tc.checks {
				assertDNSRules(t, c, chk.epID, chk.pp, chk.serverIDs, chk.patterns)
			}
		})
	}
}

func updateMapping(t *testing.T, client *GRPCClient, id uint64, ident identity.NumericIdentity, ip string) {
	t.Helper()
	ipBytes, err := netip.MustParsePrefix(ip).MarshalBinary()
	require.NoError(t, err)
	input := []*pb.IdentityToEndpointMapping{
		{
			Identity: ident.Uint32(),
			EndpointInfo: []*pb.EndpointInfo{
				{
					Id: id,
					Ip: [][]byte{ipBytes},
				},
			},
		},
	}

	err = client.updateIPToEndpoint(input)
	require.NoError(t, err)
}

func checkMapping(t *testing.T, client *GRPCClient, ip string, expectedID uint64, expectedIdent identity.NumericIdentity, shouldExist bool) {
	t.Helper()
	rtxn := client.db.ReadTxn()
	prefix, err := netip.ParsePrefix(ip)
	require.NoError(t, err)
	mapping, _, found := client.ipToEndpointTable.Get(rtxn, IdIPToEndpointIndex.Query(prefix))
	if shouldExist {
		require.True(t, found)
		require.Equal(t, prefix, mapping.IP)
		require.Equal(t, expectedIdent, mapping.Endpoint.Identity)
		require.Equal(t, expectedID, mapping.Endpoint.ID)
	} else {
		require.False(t, found)
	}
}

func TestNewIPtoIdentityTable(t *testing.T) {
	// Create a new StateDB instance
	db := statedb.New()

	// Test successful table creation
	ipTable, err := NewIPtoEndpointTable(db)
	require.NoError(t, err)
	require.NotNil(t, ipTable)

	// Create DNSRules and IPtoIdentity tables
	dnsTable, err := newDNSRulesTable(db)
	require.NoError(t, err)
	require.NotNil(t, dnsTable)

	logger := hivetest.Logger(t)
	client := &GRPCClient{
		logger:            logger,
		db:                db,
		ipToEndpointTable: ipTable,
	}

	// Initial check - table should be empty
	checkMapping(t, client, "192.168.1.1/32", 100, identity.NumericIdentity(1), false)
	checkMapping(t, client, "192.168.1.2/32", 200, identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.1, identity 1, ID 100
	updateMapping(t, client, 100, identity.NumericIdentity(1), "192.168.1.1/32")
	checkMapping(t, client, "192.168.1.1/32", 100, identity.NumericIdentity(1), true)
	checkMapping(t, client, "192.168.1.2/32", 200, identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.2, identity 2, ID 200
	updateMapping(t, client, 200, identity.NumericIdentity(2), "192.168.1.2/32")
	checkMapping(t, client, "192.168.1.2/32", 200, identity.NumericIdentity(2), true)
	checkMapping(t, client, "192.168.1.1/32", 100, identity.NumericIdentity(1), false)

	// Update mapping - modify existing entry
	updateMapping(t, client, 200, identity.NumericIdentity(3), "192.168.1.2/32")
	checkMapping(t, client, "192.168.1.2/32", 200, identity.NumericIdentity(3), true)
}
