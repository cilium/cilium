// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/lookup"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/messagehandler"
)

var (
	epID1        = uint32(111)
	epID2        = uint32(222)
	epID3        = uint32(333)
	dstID1       = identity.NumericIdentity(1001)
	dstPort53UDP = restore.MakeV2PortProto(53, u8proto.UDP)
)

func TestStandaloneDNSProxy(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	// Enable L7 proxy for the standalone DNS proxy
	option.Config.EnableL7Proxy = true
	var connHandler client.ConnectionHandler
	h := hive.New(
		StandaloneDNSProxyCell,
		cell.Invoke(func(ch client.ConnectionHandler) {
			connHandler = ch
		}),
	)

	hive.AddConfigOverride(
		h,
		func(cfg *service.FQDNConfig) {
			cfg.EnableStandaloneDNSProxy = true
		})

	err := h.Populate(hivetest.Logger(t))
	assert.NoError(t, err, "Populate()")
	connHandler.StopConnection()
}

func setupTestEnv(t *testing.T) *StandaloneDNSProxy {
	var sdp *StandaloneDNSProxy
	h := hive.New(
		cell.Module(
			"test-standalone-dns-proxy",
			"Test standalone DNS proxy",
			cell.Config(service.DefaultConfig),
			client.Cell,
			bootstrap.Cell,
			lookup.Cell,
			messagehandler.Cell,
			ReadinessCell,
			cell.Provide(
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableL7Proxy:    true,
						ToFQDNsProxyPort: 1001,
					}
				},
				NewStandaloneDNSProxy,
				NewReadinessStatusProvider,
			)),
		cell.Invoke(func(_s *StandaloneDNSProxy) {
			sdp = _s
		}))

	hive.AddConfigOverride(
		h,
		func(cfg *service.FQDNConfig) {
			cfg.EnableStandaloneDNSProxy = true
			cfg.StandaloneDNSProxyServerPort = 1000
		})
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	t.Cleanup(func() {
		// Stop the server
		if err := h.Stop(tlog, context.TODO()); err != nil {
			t.Fatalf("failed to stop: %s", err)
		}
	})
	return sdp
}

func addDataToDNSTable(t *testing.T, sdp *StandaloneDNSProxy, epID uint32, pp restore.PortProto, serverID identity.NumericIdentitySlice, patterns []string) {
	t.Helper()
	wtxn := sdp.db.WriteTxn(sdp.dnsRulesTable)
	defer wtxn.Abort()
	var pat []api.PortRuleDNS
	for _, pattern := range patterns {
		pat = append(pat, api.PortRuleDNS{
			MatchPattern: pattern,
		})
	}
	dnsRule := make(policy.L7DataMap)
	dnsRule[&client.DNSServerIdentity{Identities: serverID}] = &policy.PerSelectorPolicy{
		Verdict: types.Allow,
		L7Rules: api.L7Rules{
			DNS: pat,
		},
	}
	_, _, err := sdp.dnsRulesTable.Insert(wtxn, client.DNSRules{
		EndpointID: epID,
		PortProto:  pp,
		DNSRule:    dnsRule,
	})
	require.NoError(t, err, "failed to insert DNSRules")
	wtxn.Commit()
}

func check(t *testing.T, sdp *StandaloneDNSProxy, epID uint32, pp restore.PortProto, dstID identity.NumericIdentity, q string, expect bool) {
	t.Helper()
	allowed, err := sdp.dnsProxier.(*dnsproxy.DNSProxy).CheckAllowed(uint64(epID), pp, dstID, netip.Addr{}, q)
	require.NoError(t, err)
	if expect {
		require.True(t, allowed, "expected allow %s", q)
	} else {
		require.False(t, allowed, "expected deny %s", q)
	}
}

func TestUpdateDNSRules(t *testing.T) {
	sdp := setupTestEnv(t)
	sdp.StartStandaloneDNSProxy()
	defer sdp.StopStandaloneDNSProxy()

	// single pattern single server allow/deny other ep
	addDataToDNSTable(t, sdp, epID1, dstPort53UDP, identity.NumericIdentitySlice{dstID1}, []string{"cilium.io."})
	err := testutils.WaitUntilWithSleep(func() bool {
		rules, err := sdp.dnsProxier.GetRules(uint16(epID1))
		return err == nil && len(rules) != 0
	}, 5*time.Second, time.Millisecond*500)
	require.NoError(t, err, "failed to get rules for endpoint")

	check(t, sdp, epID1, dstPort53UDP, dstID1, "cilium.io.", true)
	check(t, sdp, epID1, dstPort53UDP, dstID1, "ciliumXio.", false)
	check(t, sdp, epID2, dstPort53UDP, dstID1, "cilium.io.", false)
	check(t, sdp, epID1, dstPort53UDP, dstID1, "ciliumXio.", false)

	// No patterns means allow all
	addDataToDNSTable(t, sdp, epID2, dstPort53UDP, identity.NumericIdentitySlice{dstID1}, []string{})
	err = testutils.WaitUntilWithSleep(func() bool {
		rules, err := sdp.dnsProxier.GetRules(uint16(epID2))
		return err == nil && len(rules) != 0
	}, 5*time.Second, time.Millisecond*500)
	require.NoError(t, err, "failed to get rules for endpoint")
	check(t, sdp, epID2, dstPort53UDP, dstID1, "cilium.io.", true)
	check(t, sdp, epID2, dstPort53UDP, dstID1, "example.com.", true)
	check(t, sdp, epID3, dstPort53UDP, dstID1, "anything.test.", false)

	// multiple patterns single server
	addDataToDNSTable(t, sdp, epID3, dstPort53UDP, identity.NumericIdentitySlice{dstID1}, []string{"example.*", "cilium.io."})
	err = testutils.WaitUntilWithSleep(func() bool {
		rules, err := sdp.dnsProxier.GetRules(uint16(epID3))
		return err == nil && len(rules) != 0
	}, 5*time.Second, time.Millisecond*500)
	require.NoError(t, err, "failed to get rules for endpoint")
	check(t, sdp, epID3, dstPort53UDP, dstID1, "cilium.io.", true)
	check(t, sdp, epID3, dstPort53UDP, dstID1, "example.com.", true)
	check(t, sdp, epID3, dstPort53UDP, dstID1, "test.example.com.", false)
}

func TestUpdateDNSRulesRevert(t *testing.T) {
	sdp := setupTestEnv(t)

	pp := restore.MakeV2PortProto(53, u8proto.UDP)
	addDataToDNSTable(t, sdp, epID1, pp, identity.NumericIdentitySlice{dstID1}, []string{"cilium.io."})
	addDataToDNSTable(t, sdp, epID2, pp, identity.NumericIdentitySlice{dstID1}, []string{"example.com."})
	rules := sdp.dnsRulesTable.All(sdp.db.ReadTxn())
	err := sdp.updateDNSRules(rules)
	require.NoError(t, err)
	check(t, sdp, epID1, pp, dstID1, "cilium.io.", true)
	check(t, sdp, epID2, pp, dstID1, "example.com.", true)

	// Now add a invalid regex to check the revert
	addDataToDNSTable(t, sdp, epID1, pp, identity.NumericIdentitySlice{dstID1}, []string{"example.com."})
	addDataToDNSTable(t, sdp, epID2, pp, identity.NumericIdentitySlice{dstID1}, []string{"(?<=a)"})
	rules = sdp.dnsRulesTable.All(sdp.db.ReadTxn())
	err = sdp.updateDNSRules(rules)
	require.Error(t, err)
	check(t, sdp, epID1, pp, dstID1, "cilium.io.", true)
	check(t, sdp, epID2, pp, dstID1, "example.com.", true)
}
