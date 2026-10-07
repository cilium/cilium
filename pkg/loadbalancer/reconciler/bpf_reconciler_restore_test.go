// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
)

// restoreEnv drives BPFOps through ResetAndRestore, Update, Delete and Prune
// against BPF maps pre-seeded with the entries of a previous agent.
type restoreEnv struct {
	t      *testing.T
	ops    *BPFOps
	lbmaps *faultyLBMaps
	fresh  int
}

func newRestoreEnv(t *testing.T) *restoreEnv {
	t.Helper()
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)

	maglevCfg, err := maglev.UserConfig{TableSize: 1021, HashSeed: maglev.DefaultHashSeed}.ToConfig()
	require.NoError(t, err, "ToConfig")
	extCfg := loadbalancer.ExternalConfig{
		ZoneMapper:           &option.DaemonConfig{},
		EnableIPv4:           true,
		EnableIPv6:           true,
		KubeProxyReplacement: true,
		DefaultLBServiceIPAM: "lbipam",
		EnableLBIPAM:         true,
	}
	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, &option.DaemonConfig{})
	cfg.LBAlgorithm = loadbalancer.LBAlgorithmRandom

	var rawMaps maps.LBMaps
	if testutils.IsPrivileged() {
		r := &maps.BPFLBMaps{Log: log, Pinned: false, Cfg: cfg, ExtCfg: extCfg, MaglevCfg: maglevCfg}
		lc.Append(r)
		rawMaps = r
	} else {
		rawMaps = maps.NewFakeLBMaps()
	}
	lbmaps := &faultyLBMaps{LBMaps: rawMaps}

	db := statedb.New()
	nodeAddrs, err := tables.NewNodeAddressTable(db)
	require.NoError(t, err)
	frontends, err := loadbalancer.NewFrontendsTable(cfg, db)
	require.NoError(t, err)

	ops := newBPFOps(bpfOpsParams{
		Lifecycle:      lc,
		Log:            log,
		Config:         cfg,
		ExternalConfig: extCfg,
		LBMaps:         lbmaps,
		Maglev:         maglev.New(maglevCfg, lc),
		DB:             db,
		NodeAddresses:  nodeAddrs,
		Frontends:      frontends,
		Metrics:        newReconcilerMetrics(),
	})
	return &restoreEnv{t: t, ops: ops, lbmaps: lbmaps}
}

func restoreAddr(proto loadbalancer.L4Type, ip string, port uint16) loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(proto, types.MustParseAddrCluster(ip), port, loadbalancer.ScopeExternal)
}

// The aliases of a service restored from a legacy ANY entry.
const aliasID = loadbalancer.ServiceID(3)

var (
	aliasANY = restoreAddr(loadbalancer.ANY, "172.18.0.10", 53)
	aliasTCP = restoreAddr(loadbalancer.TCP, "172.18.0.10", 53)
	aliasUDP = restoreAddr(loadbalancer.UDP, "172.18.0.10", 53)
)

// seed writes the master service slot and reverse NAT entry an earlier agent left behind.
func (e *restoreEnv) seed(addr loadbalancer.L3n4Addr, id loadbalancer.ServiceID) {
	e.t.Helper()
	proto := loadbalancer.L4TypeAsProtocolNumber(addr.Protocol())
	var key maps.ServiceKey
	var val maps.ServiceValue
	var revNatKey maps.RevNatKey
	if addr.IsIPv6() {
		key = maps.NewService6Key(addr.Addr(), addr.Port(), proto, addr.Scope(), 0)
		val = &maps.Service6Value{}
		revNatKey = maps.NewRevNat6Key(uint16(id))
	} else {
		key = maps.NewService4Key(addr.Addr(), addr.Port(), proto, addr.Scope(), 0)
		val = &maps.Service4Value{}
		revNatKey = maps.NewRevNat4Key(id)
	}
	val.SetRevNat(int(id))
	require.NoError(e.t, e.lbmaps.UpdateService(key.ToNetwork(), val.ToNetwork()))
	require.NoError(e.t, e.lbmaps.UpdateRevNat(revNatKey.ToNetwork(), key.RevNatValue().ToNetwork()))
}

// useMaglev makes the frontends use Maglev, which needs backends to program a table.
func (e *restoreEnv) useMaglev() {
	e.ops.cfg.LBAlgorithm = loadbalancer.LBAlgorithmMaglev
	e.ops.cfg.ExternalClusterIP = true
}

// maglevOuters returns whether the IPv4 and IPv6 Maglev maps have an outer entry for the ID.
func (e *restoreEnv) maglevOuters(id loadbalancer.ServiceID) (v4, v6 bool) {
	e.t.Helper()
	require.NoError(e.t, e.lbmaps.DumpMaglev(func(k maps.MaglevOuterKey, _ maps.MaglevOuterVal, _ maps.MaglevInnerKey, _ *maps.MaglevInnerVal, ipv6 bool) {
		if loadbalancer.ServiceID(k.RevNatID) == id {
			v4 = v4 || !ipv6
			v6 = v6 || ipv6
		}
	}))
	return
}

// revNats returns whether the IPv4 and IPv6 reverse NAT maps have an entry for the ID.
func (e *restoreEnv) revNats(id loadbalancer.ServiceID) (v4, v6 bool) {
	e.t.Helper()
	require.NoError(e.t, e.lbmaps.DumpRevNat(func(k maps.RevNatKey, _ maps.RevNatValue) {
		if k.ToHost().GetKey() == id {
			_, ipv6 := k.(*maps.RevNat6Key)
			v4 = v4 || !ipv6
			v6 = v6 || ipv6
		}
	}))
	return
}

// seedMaglev writes a Maglev outer entry an earlier agent left behind.
func (e *restoreEnv) seedMaglev(id loadbalancer.ServiceID, ipv6 bool) {
	e.t.Helper()
	table := slices.Repeat([]loadbalancer.BackendID{1}, int(e.ops.maglev.TableSize))
	require.NoError(e.t, e.lbmaps.UpdateMaglev(maps.MaglevOuterKey{RevNatID: uint16(id)}, table, ipv6))
}

// requireRevNats checks the reverse NAT entries of the ID in the IPv4 and IPv6 maps.
// The fake maps do not tell the families apart, so this is only checked with the real maps.
func (e *restoreEnv) requireRevNats(id loadbalancer.ServiceID, want4, want6 bool, msg string) {
	e.t.Helper()
	if !testutils.IsPrivileged() {
		return
	}
	got4, got6 := e.revNats(id)
	require.Equal(e.t, want4, got4, "IPv4 reverse NAT entry: "+msg)
	require.Equal(e.t, want6, got6, "IPv6 reverse NAT entry: "+msg)
}

// seedBackend writes a backend with the legacy protocol ANY.
func (e *restoreEnv) seedBackend(addr loadbalancer.L3n4Addr, id loadbalancer.BackendID) {
	e.t.Helper()
	be, err := maps.NewBackend4V3(id, addr.AddrCluster(), addr.Port(), u8proto.ANY, loadbalancer.BackendStateActive, 0)
	require.NoError(e.t, err)
	require.NoError(e.t, e.lbmaps.UpdateBackend(be.GetKey(), be.GetValue().ToNetwork()))
}

func (e *restoreEnv) restore() {
	e.t.Helper()
	require.NoError(e.t, e.ops.ResetAndRestore())
}

// frontendAt returns a ClusterIP frontend with the given address.
func frontendAt(addr loadbalancer.L3n4Addr) *loadbalancer.Frontend {
	svc := baseService
	fe := baseFrontend
	fe.Type = ClusterIP
	fe.Address = addr
	fe.Service = &svc
	return &fe
}

func (e *restoreEnv) updateFrontend(fe *loadbalancer.Frontend) loadbalancer.ServiceID {
	e.t.Helper()
	require.NoError(e.t, e.ops.Update(e.t.Context(), e.ops.db.ReadTxn(), 0, fe))
	return fe.ID
}

func (e *restoreEnv) update(addr loadbalancer.L3n4Addr) loadbalancer.ServiceID {
	e.t.Helper()
	return e.updateFrontend(frontendAt(addr))
}

func (e *restoreEnv) delete(addr loadbalancer.L3n4Addr) {
	e.t.Helper()
	require.NoError(e.t, e.ops.Delete(e.t.Context(), nil, 0, frontendAt(addr)))
}

func (e *restoreEnv) prune() {
	e.t.Helper()
	require.NoError(e.t, e.ops.Prune(e.t.Context(), nil, nil))
}

// updateFresh updates a frontend that was not present in the restored maps.
func (e *restoreEnv) updateFresh() loadbalancer.ServiceID {
	e.t.Helper()
	e.fresh++
	return e.update(restoreAddr(loadbalancer.TCP, fmt.Sprintf("10.200.%d.%d", e.fresh/250, e.fresh%250+1), 80))
}

// freshAllocationsReach rewinds the allocator, as it does on wrapping, and
// reports whether any of the next n fresh frontends is assigned id.
func (e *restoreEnv) freshAllocationsReach(id loadbalancer.ServiceID, n int) bool {
	e.t.Helper()
	e.ops.serviceIDAlloc.nextID = firstFreeServiceID
	reached := false
	for range n {
		reached = e.updateFresh() == id || reached
	}
	return reached
}

func (e *restoreEnv) hasMaster(addr loadbalancer.L3n4Addr) (found bool) {
	e.t.Helper()
	require.NoError(e.t, e.lbmaps.DumpService(func(k maps.ServiceKey, _ maps.ServiceValue) {
		k = k.ToHost()
		found = found || (k.GetBackendSlot() == 0 && svcKeyToAddr(k) == addr)
	}))
	return
}

// affinityMatches returns the backend IDs with an affinity match for the service ID.
func (e *restoreEnv) affinityMatches(id loadbalancer.ServiceID) (out []loadbalancer.BackendID) {
	e.t.Helper()
	require.NoError(e.t, e.lbmaps.DumpAffinityMatch(func(k *maps.AffinityMatchKey, _ *maps.AffinityMatchValue) {
		k = k.ToHost()
		if k.RevNATID == uint16(id) {
			out = append(out, k.BackendID)
		}
	}))
	return
}

// sourceRanges returns the source ranges of the service ID.
func (e *restoreEnv) sourceRanges(id loadbalancer.ServiceID) (out []netip.Prefix) {
	e.t.Helper()
	require.NoError(e.t, e.lbmaps.DumpSourceRange(func(k maps.SourceRangeKey, _ *maps.SourceRangeValue) {
		k = k.ToHost()
		if k.GetRevNATID() == id {
			out = append(out, k.GetPrefix())
		}
	}))
	return
}

// TestRestoredServiceIDsAreReserved: a restored ID must not be handed to a fresh
// frontend that is updated before the restored frontend, even when the allocator
// has wrapped around because the highest restored ID is next to the maximum.
func TestRestoredServiceIDsAreReserved(t *testing.T) {
	const lowID = loadbalancer.ServiceID(3)
	highID := maxSetOfServiceID - 1
	restoredLow := restoreAddr(loadbalancer.TCP, "172.18.17.138", 80)
	restoredHigh := restoreAddr(loadbalancer.TCP, "172.18.5.5", 8080)

	e := newRestoreEnv(t)
	e.seed(restoredLow, lowID)
	e.seed(restoredHigh, highID)
	e.restore()

	seen := map[loadbalancer.ServiceID]bool{}
	for range 10 {
		id := e.updateFresh()
		require.NotEqual(t, lowID, id, "fresh frontend got pending restored ID")
		require.NotEqual(t, highID, id, "fresh frontend got pending restored ID")
		require.False(t, seen[id], "fresh frontends share ID %d", id)
		seen[id] = true
	}

	require.Equal(t, lowID, e.update(restoredLow), "restored frontend ID")
	require.Equal(t, highID, e.update(restoredHigh), "restored frontend ID")
}

// TestRestoredServiceIDAliases: legacy ANY entries are restored as TCP/UDP/SCTP
// aliases sharing one ID. The ID and the state keyed by it stay until the last
// alias is deleted.
func TestRestoredServiceIDAliases(t *testing.T) {
	e := newRestoreEnv(t)
	e.seed(aliasANY, aliasID)
	e.restore()

	require.Equal(t, aliasID, e.update(aliasTCP))
	require.Equal(t, aliasID, e.update(aliasUDP))
	e.prune() // drops the legacy ANY slot and the unclaimed SCTP alias

	e.delete(aliasTCP)
	require.True(t, e.hasMaster(aliasUDP), "sibling alias lost its service slot")
	require.False(t, e.hasMaster(aliasTCP), "deleted alias kept its service slot")
	r4, _ := e.revNats(aliasID)
	require.True(t, r4, "reverse NAT removed while sibling alias remains")
	require.False(t, e.freshAllocationsReach(aliasID, 5), "ID reused while sibling alias remains")

	e.delete(aliasUDP)
	require.False(t, e.hasMaster(aliasUDP))
	r4, _ = e.revNats(aliasID)
	require.False(t, r4, "reverse NAT remains after last alias was deleted")
	require.True(t, e.freshAllocationsReach(aliasID, 5), "ID not released after last alias was deleted")
}

// TestUnclaimedRestoredServiceIDIsReleasedByPrune: a restored ID that no frontend
// claims stays reserved until Prune has removed its stale state. It is not released
// if removing the state fails.
func TestUnclaimedRestoredServiceIDIsReleasedByPrune(t *testing.T) {
	const id = loadbalancer.ServiceID(3)
	stale := restoreAddr(loadbalancer.TCP, "172.18.17.138", 80)
	staleRange := netip.MustParsePrefix("10.0.0.0/8")

	for _, tc := range []struct {
		name  string
		setup func(e *restoreEnv)
		// failure returns the failure injection flag that makes Prune fail.
		failure func(m *faultyLBMaps) *bool
		// gone checks that the stale state was removed.
		gone func(t *testing.T, e *restoreEnv)
	}{
		{
			name: "delete_service",
			setup: func(e *restoreEnv) {
				e.seed(stale, id)
				e.restore()
			},
			failure: func(m *faultyLBMaps) *bool { return &m.failDeleteService },
			gone: func(t *testing.T, e *restoreEnv) {
				require.False(t, e.hasMaster(stale), "stale service slot survived Prune")
				r4, _ := e.revNats(id)
				require.False(t, r4, "stale reverse NAT survived Prune")
			},
		},
		{
			name: "dump_service",
			setup: func(e *restoreEnv) {
				e.seed(stale, id)
				e.restore()
			},
			failure: func(m *faultyLBMaps) *bool { return &m.failDumpService },
			gone: func(t *testing.T, e *restoreEnv) {
				require.False(t, e.hasMaster(stale), "stale service slot survived Prune")
			},
		},
		{
			name: "delete_source_range",
			setup: func(e *restoreEnv) {
				e.seed(stale, id)
				require.NoError(e.t, e.lbmaps.UpdateSourceRange(srcRangeKey(staleRange, uint16(id), false), &maps.SourceRangeValue{}))
				e.restore()
			},
			failure: func(m *faultyLBMaps) *bool { return &m.failDeleteSourceRange },
			gone: func(t *testing.T, e *restoreEnv) {
				require.Empty(t, e.sourceRanges(id), "stale source range survived Prune")
			},
		},
		{
			// The unclaimed aliases are the last owners of the wildcard entry of the IP.
			name: "delete_wildcard",
			setup: func(e *restoreEnv) {
				e.seed(aliasANY, aliasID)
				e.restore()
				require.Equal(e.t, aliasID, e.update(aliasTCP))
				require.NotEmpty(e.t, e.ops.wildcardReferences, "wildcard not programmed")
				e.delete(aliasTCP)
				require.NotEmpty(e.t, e.ops.wildcardReferences, "wildcard removed while unclaimed aliases hold the ID")
			},
			failure: func(m *faultyLBMaps) *bool { return &m.failDeleteWildcard },
			gone: func(t *testing.T, e *restoreEnv) {
				require.NotContains(t, e.ops.wildcardReferences, aliasANY.Addr(), "wildcard reference survived Prune")
				require.False(t, e.hasMaster(loadbalancer.NewL3n4Addr(loadbalancer.ANY, aliasANY.AddrCluster(), WildcardPortNumber, aliasANY.Scope())), "wildcard service entry survived Prune")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRestoreEnv(t)
			tc.setup(e)

			require.False(t, e.freshAllocationsReach(id, 5), "unclaimed restored ID reused before Prune")

			flag := tc.failure(e.lbmaps)
			*flag = true
			require.Error(t, e.ops.Prune(t.Context(), nil, nil))
			*flag = false
			require.NotEmpty(t, e.ops.restoredServiceIDs, "restored ID forgotten after failed Prune")
			require.False(t, e.freshAllocationsReach(id, 5), "restored ID reused after failed Prune")

			e.prune()
			tc.gone(t, e)
			require.Empty(t, e.ops.restoredServiceIDs)
			require.True(t, e.freshAllocationsReach(id, 5), "unclaimed restored ID not released by Prune")
		})
	}
}

// TestRestoredServiceIDWithTwoIDs: an address restored with two IDs, from a legacy
// ANY entry and an explicit entry, claims one of them. The other one is released by
// Prune together with its stale state, and nothing is left once the address is deleted.
func TestRestoredServiceIDWithTwoIDs(t *testing.T) {
	anyAddr := restoreAddr(loadbalancer.ANY, "172.18.0.10", 80)
	tcp := restoreAddr(loadbalancer.TCP, "172.18.0.10", 80)

	e := newRestoreEnv(t)
	e.seed(anyAddr, 3)
	e.seed(tcp, 4)
	e.seedMaglev(3, false)
	e.seedMaglev(4, false)
	e.restore()

	claimed := e.update(tcp)
	require.Contains(t, []loadbalancer.ServiceID{3, 4}, claimed)
	lost := loadbalancer.ServiceID(7) - claimed
	e.prune()
	require.Len(t, e.ops.serviceIDAlloc.idToAddrs, 1, "reservations after Prune")
	require.Equal(t, claimed, e.ops.serviceIDAlloc.addrToId[tcp])
	m4, _ := e.maglevOuters(lost)
	require.False(t, m4, "stale Maglev outer entry of the released ID survived Prune")
	r4, _ := e.revNats(lost)
	require.False(t, r4, "stale reverse NAT entry of the released ID survived Prune")

	e.delete(tcp)
	e.prune()
	require.Empty(t, e.ops.serviceIDAlloc.idToAddrs, "reservations remain")
	require.True(t, e.lbmaps.IsEmpty(), "BPF maps after Prune")
}

// TestRestoredServiceIDLostReservation: an address restored with two IDs (legacy ANY 3
// and explicit TCP 4) that claims 4 is not an owner of 3 for the state keyed by the ID
// and something else. Its source ranges and backends belong to 4.
func TestRestoredServiceIDLostReservation(t *testing.T) {
	const lost, claimed = loadbalancer.ServiceID(3), loadbalancer.ServiceID(4)
	tcp := restoreAddr(loadbalancer.TCP, "172.18.0.10", 80)
	udp := restoreAddr(loadbalancer.UDP, "172.18.0.10", 80)
	staleRange := netip.MustParsePrefix("10.0.0.0/8")

	newEnv := func(t *testing.T) *restoreEnv {
		e := newRestoreEnv(t)
		e.seed(restoreAddr(loadbalancer.ANY, "172.18.0.10", 80), lost)
		e.seed(tcp, claimed)
		// The backends of both aliases share an ID, as for a legacy ANY backend.
		e.seedBackend(restoreAddr(loadbalancer.ANY, "10.1.0.1", 8080), 7)
		return e
	}
	// restore makes the TCP frontend claim 4, which depends on the order of the restored maps.
	restore := func(e *restoreEnv) {
		e.restore()
		require.Contains(e.t, []loadbalancer.ServiceID{lost, claimed}, e.ops.restoredServiceIDs[tcp])
		e.ops.restoredServiceIDs[tcp] = claimed
	}
	update := func(e *restoreEnv, addr loadbalancer.L3n4Addr, affinity bool) loadbalancer.ServiceID {
		fe := frontendAt(addr)
		fe.Service.SourceRanges = []netip.Prefix{staleRange}
		fe.Service.SessionAffinity = affinity
		fe.Backends = concatBe(fe.Backends, newTestBackend(restoreAddr(addr.Protocol(), "10.1.0.1", 8080), loadbalancer.BackendStateActive), 1)
		return e.updateFrontend(fe)
	}

	t.Run("prune_source_range", func(t *testing.T) {
		e := newEnv(t)
		require.NoError(t, e.lbmaps.UpdateSourceRange(srcRangeKey(staleRange, uint16(lost), false), &maps.SourceRangeValue{}))
		restore(e)
		require.Equal(t, claimed, update(e, tcp, false))
		e.prune()
		require.Empty(t, e.sourceRanges(lost), "stale source range of the released ID survived Prune")
		require.Equal(t, []netip.Prefix{staleRange}, e.sourceRanges(claimed))
	})

	t.Run("delete_source_range", func(t *testing.T) {
		e := newEnv(t)
		restore(e)
		require.Equal(t, claimed, update(e, tcp, false))
		require.Equal(t, lost, update(e, udp, false))
		e.delete(udp)
		require.Empty(t, e.sourceRanges(lost), "source range of the deleted alias remains")
		require.Equal(t, []netip.Prefix{staleRange}, e.sourceRanges(claimed))
	})

	t.Run("delete_affinity_match", func(t *testing.T) {
		e := newEnv(t)
		restore(e)
		require.Equal(t, claimed, update(e, tcp, true))
		require.Equal(t, lost, update(e, udp, true))
		require.Len(t, e.affinityMatches(lost), 1)
		e.delete(udp)
		require.Empty(t, e.affinityMatches(lost), "affinity match of the deleted alias remains")
		require.Len(t, e.affinityMatches(claimed), 1)
	})
}

// TestRestoredServiceIDWildcardEntries: the wildcard entries have the revNAT 0, which
// is not an allocatable ID and is not reserved.
func TestRestoredServiceIDWildcardEntries(t *testing.T) {
	wild := restoreAddr(loadbalancer.ANY, "172.18.0.10", 0)

	e := newRestoreEnv(t)
	e.seed(wild, 0)
	e.restore()
	require.NotEmpty(t, e.ops.restoredServiceIDs)
	require.Empty(t, e.ops.serviceIDAlloc.idToAddrs, "wildcard entries reserve ID 0")

	e.prune()
	require.Empty(t, e.ops.restoredServiceIDs)
}

// TestRestoredServiceIDAliasMaglev: the Maglev outer entry of an ID is removed with
// the last owner.
func TestRestoredServiceIDAliasMaglev(t *testing.T) {
	e := newRestoreEnv(t)
	e.useMaglev()
	e.seed(aliasANY, aliasID)
	e.restore()
	for _, addr := range []loadbalancer.L3n4Addr{aliasTCP, aliasUDP} {
		fe := frontendAt(addr)
		fe.Backends = concatBe(fe.Backends, newTestBackend(restoreAddr(addr.Protocol(), "10.1.0.1", 53), loadbalancer.BackendStateActive), 1)
		require.Equal(t, aliasID, e.updateFrontend(fe))
	}

	e.delete(aliasTCP)
	v4, _ := e.maglevOuters(aliasID)
	require.True(t, v4, "sibling alias lost its Maglev outer entry")

	e.delete(aliasUDP)
	e.prune()
	v4, _ = e.maglevOuters(aliasID)
	require.False(t, v4, "Maglev outer entry remains after the last alias was deleted")
}

// TestRestoredServiceIDSharedByIPFamilies: the reverse NAT and Maglev maps are separate
// for IPv4 and IPv6. Their entries of an ID that frontends of both families own
// (restored from maps with colliding IDs) go with the last owner of the family.
func TestRestoredServiceIDSharedByIPFamilies(t *testing.T) {
	const id = loadbalancer.ServiceID(3)
	v4 := restoreAddr(loadbalancer.TCP, "172.18.0.10", 80)
	v6 := restoreAddr(loadbalancer.TCP, "fd00::10", 80)

	e := newRestoreEnv(t)
	e.useMaglev()
	e.seed(v4, id)
	e.seed(v6, id)
	e.restore()
	for _, addr := range []loadbalancer.L3n4Addr{v4, v6} {
		backend := "10.1.0.1"
		if addr.IsIPv6() {
			backend = "fd01::1"
		}
		fe := frontendAt(addr)
		fe.Backends = concatBe(fe.Backends, newTestBackend(restoreAddr(loadbalancer.TCP, backend, 80), loadbalancer.BackendStateActive), 1)
		require.Equal(t, id, e.updateFrontend(fe))
	}
	e.prune()
	m4, m6 := e.maglevOuters(id)
	require.True(t, m4 && m6, "Maglev outer entries before Delete")

	check := func(when string) {
		m4, m6 := e.maglevOuters(id)
		require.False(t, m4, "IPv4 Maglev outer entry of the deleted frontend remains "+when)
		require.True(t, m6, "IPv6 Maglev outer entry of the remaining frontend was removed "+when)
		e.requireRevNats(id, false, true, when)
	}

	e.delete(v4)
	check("after Delete")
	e.prune()
	check("after Prune")

	e.delete(v6)
	e.prune()
	require.True(t, e.lbmaps.IsEmpty(), "BPF maps after deleting both frontends")
}

// TestRestoredServiceIDAliasAffinity: the affinity matches of a deleted alias are
// removed unless another alias still uses the same backend.
func TestRestoredServiceIDAliasAffinity(t *testing.T) {
	for _, tc := range []struct {
		name string
		// restoredBackend gives the aliases the same backend ID, as it happens for a legacy ANY backend.
		restoredBackend bool
		wantMatches     int
	}{
		{name: "distinct_backends", wantMatches: 2},
		{name: "shared_backend", restoredBackend: true, wantMatches: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRestoreEnv(t)
			e.seed(aliasANY, aliasID)
			if tc.restoredBackend {
				e.seedBackend(restoreAddr(loadbalancer.ANY, "10.1.0.1", 80), 7)
			}
			e.restore()

			for _, addr := range []loadbalancer.L3n4Addr{aliasTCP, aliasUDP} {
				fe := frontendAt(addr)
				fe.Service.SessionAffinity = true
				fe.Backends = concatBe(fe.Backends, newTestBackend(restoreAddr(addr.Protocol(), "10.1.0.1", 80), loadbalancer.BackendStateActive), 1)
				require.Equal(t, aliasID, e.updateFrontend(fe))
			}
			require.Len(t, e.affinityMatches(aliasID), tc.wantMatches)

			e.delete(aliasTCP)
			require.Len(t, e.affinityMatches(aliasID), 1, "affinity match of the sibling alias")

			e.delete(aliasUDP)
			require.Empty(t, e.affinityMatches(aliasID), "affinity matches remain")
			e.prune()
			require.True(t, e.lbmaps.IsEmpty(), "BPF maps after Prune")
		})
	}
}

// TestRestoredServiceIDAliasSourceRanges: the source ranges of a deleted alias are
// removed unless another alias still has them.
func TestRestoredServiceIDAliasSourceRanges(t *testing.T) {
	shared := netip.MustParsePrefix("192.168.0.0/16")
	tcpOnly := netip.MustParsePrefix("10.0.0.0/8")

	e := newRestoreEnv(t)
	e.seed(aliasANY, aliasID)
	e.restore()

	fe := frontendAt(aliasTCP)
	fe.Service.SourceRanges = []netip.Prefix{shared, tcpOnly}
	require.Equal(t, aliasID, e.updateFrontend(fe))
	fe = frontendAt(aliasUDP)
	fe.Service.SourceRanges = []netip.Prefix{shared}
	require.Equal(t, aliasID, e.updateFrontend(fe))
	require.ElementsMatch(t, []netip.Prefix{shared, tcpOnly}, e.sourceRanges(aliasID))

	e.delete(aliasTCP)
	require.Equal(t, []netip.Prefix{shared}, e.sourceRanges(aliasID), "source ranges after deleting the alias")

	e.delete(aliasUDP)
	require.Empty(t, e.sourceRanges(aliasID), "source ranges remain")
	e.prune()
	require.True(t, e.lbmaps.IsEmpty(), "BPF maps after Prune")
}

// TestUnclaimedRestoredServiceIDIPFamily: the stale reverse NAT and Maglev entries of an
// unclaimed restored frontend are pruned even if a frontend of the other IP family
// has claimed the same ID.
func TestUnclaimedRestoredServiceIDIPFamily(t *testing.T) {
	const id = loadbalancer.ServiceID(3)
	v4 := restoreAddr(loadbalancer.TCP, "172.18.0.10", 80)
	v6 := restoreAddr(loadbalancer.TCP, "fd00::10", 80)

	e := newRestoreEnv(t)
	e.seed(v4, id)
	e.seed(v6, id)
	e.seedMaglev(id, false)
	e.seedMaglev(id, true)
	e.restore()
	require.Equal(t, id, e.update(v6))
	e.prune()

	m4, m6 := e.maglevOuters(id)
	require.False(t, m4, "stale IPv4 Maglev outer entry survived Prune")
	require.True(t, m6, "IPv6 Maglev outer entry was removed")
	e.requireRevNats(id, false, true, "after Prune")
}
