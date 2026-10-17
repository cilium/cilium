// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	stdmaps "maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	// nodeAddrs is the node address table the NodePort and HostPort frontends are expanded with.
	nodeAddrs statedb.RWTable[tables.NodeAddress]
	fresh     int
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
	return &restoreEnv{t: t, ops: ops, lbmaps: lbmaps, nodeAddrs: nodeAddrs}
}

func restoreAddr(proto loadbalancer.L4Type, ip string, port uint16) loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(proto, types.MustParseAddrCluster(ip), port, loadbalancer.ScopeExternal)
}

// The aliases of a service restored from a legacy ANY entry.
const aliasID = loadbalancer.ServiceID(3)

var (
	aliasANY  = restoreAddr(loadbalancer.ANY, "172.18.0.10", 53)
	aliasTCP  = restoreAddr(loadbalancer.TCP, "172.18.0.10", 53)
	aliasUDP  = restoreAddr(loadbalancer.UDP, "172.18.0.10", 53)
	aliasSCTP = restoreAddr(loadbalancer.SCTP, "172.18.0.10", 53)
)

// seed writes the master service slot and reverse NAT entry an earlier agent left behind.
func (e *restoreEnv) seed(addr loadbalancer.L3n4Addr, id loadbalancer.ServiceID) {
	e.t.Helper()
	proto := loadbalancer.L4TypeAsProtocolNumber(addr.Protocol())
	var key maps.ServiceKey
	var val maps.ServiceValue
	if addr.IsIPv6() {
		key = maps.NewService6Key(addr.Addr(), addr.Port(), proto, addr.Scope(), 0)
		val = &maps.Service6Value{}
	} else {
		key = maps.NewService4Key(addr.Addr(), addr.Port(), proto, addr.Scope(), 0)
		val = &maps.Service4Value{}
	}
	val.SetRevNat(int(id))
	require.NoError(e.t, e.lbmaps.UpdateService(key.ToNetwork(), val.ToNetwork()))
	e.setRevNat(addr, id)
}

// setRevNat makes the reverse NAT entry of the ID point to the address.
func (e *restoreEnv) setRevNat(addr loadbalancer.L3n4Addr, id loadbalancer.ServiceID) {
	e.t.Helper()
	var key maps.ServiceKey
	var revNatKey maps.RevNatKey
	if addr.IsIPv6() {
		key = maps.NewService6Key(addr.Addr(), addr.Port(), 0, addr.Scope(), 0)
		revNatKey = maps.NewRevNat6Key(uint16(id))
	} else {
		key = maps.NewService4Key(addr.Addr(), addr.Port(), 0, addr.Scope(), 0)
		revNatKey = maps.NewRevNat4Key(id)
	}
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

// seedSlots writes the backend slots of an IPv4 service that was seeded.
func (e *restoreEnv) seedSlots(addr loadbalancer.L3n4Addr, id loadbalancer.ServiceID, backendIDs ...loadbalancer.BackendID) {
	e.t.Helper()
	require.False(e.t, addr.IsIPv6())
	key := maps.NewService4Key(addr.Addr(), addr.Port(), loadbalancer.L4TypeAsProtocolNumber(addr.Protocol()), addr.Scope(), 0)
	for slot, beID := range backendIDs {
		val := &maps.Service4Value{}
		val.SetRevNat(int(id))
		val.SetBackendID(beID)
		key.SetBackendSlot(slot + 1)
		require.NoError(e.t, e.lbmaps.UpdateService(key.ToNetwork(), val.ToNetwork()))
	}
}

// activeBackend returns an active backend.
func activeBackend(proto loadbalancer.L4Type, ip string, port uint16) loadbalancer.Backend {
	return newTestBackend(restoreAddr(proto, ip, port), loadbalancer.BackendStateActive)
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

// affinityFrontend returns a frontend with session affinity and the backends.
func affinityFrontend(addr loadbalancer.L3n4Addr, bes ...loadbalancer.Backend) *loadbalancer.Frontend {
	fe := frontendAt(addr)
	fe.Service.SessionAffinity = true
	for _, be := range bes {
		fe.Backends = concatBe(fe.Backends, be, 1)
	}
	return fe
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
	_, found = e.masterID(addr)
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

// masterID returns the ID in the master service entry of the address.
func (e *restoreEnv) masterID(addr loadbalancer.L3n4Addr) (id loadbalancer.ServiceID, found bool) {
	e.t.Helper()
	require.NoError(e.t, e.lbmaps.DumpService(func(k maps.ServiceKey, v maps.ServiceValue) {
		k = k.ToHost()
		if k.GetBackendSlot() == 0 && svcKeyToAddr(k) == addr {
			id, found = loadbalancer.ServiceID(v.ToHost().GetRevNat()), true
		}
	}))
	return
}

// revNatAddr returns the address the reverse NAT entry of the ID in the IPv4 map points to.
func (e *restoreEnv) revNatAddr(id loadbalancer.ServiceID) (addr netip.AddrPort, found bool) {
	e.t.Helper()
	require.NoError(e.t, e.lbmaps.DumpRevNat(func(k maps.RevNatKey, v maps.RevNatValue) {
		if v, ok := v.ToHost().(*maps.RevNat4Value); ok && k.ToHost().GetKey() == id {
			addr, found = netip.AddrPortFrom(v.Address.Addr(), v.Port), true
		}
	}))
	return
}

// recordedLogs records the log messages.
type recordedLogs struct {
	slog.Handler
	records *[]slog.Record
}

func (l recordedLogs) Handle(_ context.Context, r slog.Record) error {
	*l.records = append(*l.records, r)
	return nil
}

func (l recordedLogs) Enabled(context.Context, slog.Level) bool { return true }

// recordWarnings records the warnings of the BPFOps, unlike the logs of the test.
func (e *restoreEnv) recordWarnings() *[]slog.Record {
	records := &[]slog.Record{}
	e.ops.log = newRateLimitingLogger(slog.New(recordedLogs{Handler: slog.DiscardHandler, records: records}))
	return records
}

// requireOwns checks that the service of the address has the ID, and that the reverse
// NAT entry of the ID is its own.
func (e *restoreEnv) requireOwns(addr loadbalancer.L3n4Addr, id loadbalancer.ServiceID) {
	e.t.Helper()
	got, found := e.masterID(addr)
	require.True(e.t, found, "master of %s", addr)
	require.Equal(e.t, id, got, "master of %s", addr)
	revNat, found := e.revNatAddr(id)
	require.True(e.t, found, "reverse NAT of %s", addr)
	require.Equal(e.t, netip.AddrPortFrom(addr.Addr(), addr.Port()), revNat, "reverse NAT of %s", addr)
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
		// kept checks the state that is not removed if Prune failed, if any.
		kept func(t *testing.T, e *restoreEnv)
	}{
		{
			// The affinity match of a stale slot that could not be deleted is not deleted.
			name: "delete_service_keeps_affinity_match",
			setup: func(e *restoreEnv) {
				e.seed(stale, id)
				e.seedSlots(stale, id, 7)
				key := &maps.AffinityMatchKey{BackendID: 7, RevNATID: uint16(id)}
				require.NoError(e.t, e.lbmaps.UpdateAffinityMatch(key.ToNetwork(), &maps.AffinityMatchValue{}))
				e.restore()
			},
			failure: func(m *faultyLBMaps) *bool { return &m.failDeleteService },
			kept: func(t *testing.T, e *restoreEnv) {
				require.Len(t, e.affinityMatches(id), 1, "affinity match of the slot that was not deleted")
			},
			gone: func(t *testing.T, e *restoreEnv) {
				require.Empty(t, e.affinityMatches(id), "stale affinity match survived Prune")
			},
		},
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
		{
			name: "dump_affinity_match",
			setup: func(e *restoreEnv) {
				e.seed(stale, id)
				key := &maps.AffinityMatchKey{BackendID: 7, RevNATID: uint16(id)}
				require.NoError(e.t, e.lbmaps.UpdateAffinityMatch(key.ToNetwork(), &maps.AffinityMatchValue{}))
				e.restore()
			},
			failure: func(m *faultyLBMaps) *bool { return &m.failDumpAffinity },
			gone: func(t *testing.T, e *restoreEnv) {
				require.Empty(t, e.affinityMatches(id), "stale affinity match survived Prune")
			},
		},
		{
			name: "delete_affinity_match",
			setup: func(e *restoreEnv) {
				e.seed(stale, id)
				key := &maps.AffinityMatchKey{BackendID: 7, RevNATID: uint16(id)}
				require.NoError(e.t, e.lbmaps.UpdateAffinityMatch(key.ToNetwork(), &maps.AffinityMatchValue{}))
				e.restore()
			},
			failure: func(m *faultyLBMaps) *bool { return &m.failDeleteAffinity },
			gone: func(t *testing.T, e *restoreEnv) {
				require.Empty(t, e.affinityMatches(id), "stale affinity match survived Prune")
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
			if tc.kept != nil {
				tc.kept(t, e)
			}
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
		fe.Backends = concatBe(fe.Backends, activeBackend(addr.Protocol(), "10.1.0.1", 8080), 1)
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
// is not an allocatable ID and is not reserved. They do not collide with each other.
func TestRestoredServiceIDWildcardEntries(t *testing.T) {
	e := newRestoreEnv(t)
	warnings := e.recordWarnings()
	e.seed(restoreAddr(loadbalancer.ANY, "172.18.0.10", 0), 0)
	e.seed(restoreAddr(loadbalancer.ANY, "172.18.0.11", 0), 0)
	e.restore()
	require.Len(t, e.ops.restoredServiceIDs, 6, "TCP, UDP and SCTP of each wildcard entry")
	require.Empty(t, e.ops.serviceIDAlloc.idToAddrs, "wildcard entries reserve ID 0")
	require.Empty(t, *warnings)

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
		fe.Backends = concatBe(fe.Backends, activeBackend(addr.Protocol(), "10.1.0.1", 53), 1)
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
// (restored from maps with colliding IDs) go with the last owner of the family. The same
// ID in both families is not a collision.
func TestRestoredServiceIDSharedByIPFamilies(t *testing.T) {
	const id = loadbalancer.ServiceID(3)
	v4 := restoreAddr(loadbalancer.TCP, "172.18.0.10", 80)
	v6 := restoreAddr(loadbalancer.TCP, "fd00::10", 80)

	e := newRestoreEnv(t)
	warnings := e.recordWarnings()
	e.useMaglev()
	e.seed(v4, id)
	e.seed(v6, id)
	e.restore()
	require.Empty(t, *warnings)
	for _, addr := range []loadbalancer.L3n4Addr{v4, v6} {
		backend := "10.1.0.1"
		if addr.IsIPv6() {
			backend = "fd01::1"
		}
		fe := frontendAt(addr)
		fe.Backends = concatBe(fe.Backends, activeBackend(loadbalancer.TCP, backend, 80), 1)
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
				fe := affinityFrontend(addr, activeBackend(addr.Protocol(), "10.1.0.1", 80))
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

// recordAttrs returns the attributes of a log record.
func recordAttrs(r slog.Record) map[string]any {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	return attrs
}

// TestRestoredServiceIDCollision: an ID that was given to frontends with different
// addresses by an older agent is kept by the frontend of the reverse NAT entry. The
// other frontends get a new ID when they are updated.
func TestRestoredServiceIDCollision(t *testing.T) {
	// The address of the reverse NAT entry is higher than the one of the loser.
	owner := restoreAddr(loadbalancer.TCP, "172.18.22.213", 8000)

	e := newRestoreEnv(t)
	warnings := e.recordWarnings()
	e.seed(aliasANY, aliasID)
	e.seed(owner, aliasID)
	e.restore()

	// The aliases of the loser only reserve the ID.
	require.Equal(t, map[loadbalancer.L3n4Addr]loadbalancer.ServiceID{owner: aliasID}, e.ops.restoredServiceIDs)
	require.Equal(t, sets.New(owner, aliasTCP, aliasUDP, aliasSCTP), e.ops.serviceIDAlloc.idToAddrs[aliasID])
	require.Len(t, *warnings, 1)
	attrs := recordAttrs((*warnings)[0])
	require.Equal(t, aliasID, attrs[logfields.ID])
	require.Equal(t, "IPv4", attrs[logfields.Family])
	require.Equal(t, "172.18.22.213:8000", attrs[logfields.Frontend])
	require.Equal(t, []string{aliasANY.StringWithProtocol()}, attrs[logfields.Addresses])
	require.Equal(t, "reverse NAT entry", attrs[logfields.Reason])

	// The losers are updated first, they do not take the ID of the owner.
	tcpID, udpID := e.update(aliasTCP), e.update(aliasUDP)
	require.NotEqual(t, aliasID, tcpID)
	require.NotEqual(t, aliasID, udpID)
	require.NotEqual(t, tcpID, udpID)
	require.Equal(t, aliasID, e.update(owner))
	e.prune()

	e.requireOwns(aliasTCP, tcpID)
	e.requireOwns(aliasUDP, udpID)
	e.requireOwns(owner, aliasID)
	require.False(t, e.hasMaster(aliasANY), "stale master of the loser")

	// Everything is removed with the frontends.
	e.delete(aliasTCP)
	e.delete(aliasUDP)
	e.delete(owner)
	e.prune()
	require.True(t, e.lbmaps.IsEmpty(), "BPF maps after deleting the frontends")
	require.Empty(t, e.ops.serviceIDAlloc.idToAddrs)
}

// TestRestoredServiceIDCollisionWinner: the frontend that keeps the ID is the one of the
// reverse NAT entry, or else the one with the lowest address, which does not depend on
// the order the entries are restored in.
func TestRestoredServiceIDCollisionWinner(t *testing.T) {
	const id = loadbalancer.ServiceID(3)
	addr := func(ip string, port uint16) loadbalancer.L3n4Addr { return restoreAddr(loadbalancer.TCP, ip, port) }
	low, mid, high := addr("10.0.0.2", 80), addr("10.0.0.5", 80), addr("10.0.0.9", 80)
	node := addr("10.0.0.3", 30000)

	for _, tc := range []struct {
		name   string
		owners []loadbalancer.L3n4Addr
		// revNat is the address of the reverse NAT entry, missing if nil.
		revNat *loadbalancer.L3n4Addr
		want   loadbalancer.L3n4Addr
		// fallback is whether the lowest address is the winner.
		fallback bool
	}{
		{name: "revnat_is_not_the_lowest", owners: []loadbalancer.L3n4Addr{low, mid, high}, revNat: &high, want: high},
		{name: "revnat_missing", owners: []loadbalancer.L3n4Addr{low, mid, high}, want: low, fallback: true},
		{name: "revnat_is_not_an_owner", owners: []loadbalancer.L3n4Addr{mid, high, low}, revNat: new(addr("10.0.0.7", 80)), want: low, fallback: true},
		{name: "revnat_has_the_ip_of_an_owner", owners: []loadbalancer.L3n4Addr{low, mid, high}, revNat: new(addr("10.0.0.5", 81)), want: low, fallback: true},
		{name: "same_ip_different_ports", owners: []loadbalancer.L3n4Addr{addr("10.0.0.2", 81), addr("10.0.0.2", 80)}, want: addr("10.0.0.2", 80), fallback: true},
		// The surrogate of a NodePort frontend and a node address do not share an ID.
		{name: "surrogate_vs_node_ip", owners: []loadbalancer.L3n4Addr{addr("0.0.0.0", 30000), node}, revNat: &node, want: node},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The order of the restored entries is random.
			for range 20 {
				e := newRestoreEnv(t)
				warnings := e.recordWarnings()
				for _, owner := range tc.owners {
					e.seed(owner, id)
				}
				if tc.revNat == nil {
					require.NoError(t, e.lbmaps.DeleteRevNat(maps.NewRevNat4Key(id).ToNetwork()))
				} else {
					e.setRevNat(*tc.revNat, id)
				}
				e.restore()

				require.Equal(t, map[loadbalancer.L3n4Addr]loadbalancer.ServiceID{tc.want: id}, e.ops.restoredServiceIDs)
				require.Len(t, *warnings, 1)
				require.Equal(t, tc.fallback, recordAttrs((*warnings)[0])[logfields.Reason] == "lowest address")
			}
		})
	}
}

// TestRestoredServiceIDSharedByFrontends: the frontends that have the same IP address and
// port share a restored ID. This is the case for the protocol aliases of a legacy
// 'ANY' service after it was migrated, and for the scopes of an address.
func TestRestoredServiceIDSharedByFrontends(t *testing.T) {
	scoped := func(scope uint8) loadbalancer.L3n4Addr {
		return loadbalancer.NewL3n4Addr(loadbalancer.TCP, types.MustParseAddrCluster("172.18.0.10"), 53, scope)
	}

	for _, tc := range []struct {
		name  string
		addrs []loadbalancer.L3n4Addr
	}{
		{name: "migrated_aliases", addrs: []loadbalancer.L3n4Addr{aliasTCP, aliasUDP, aliasSCTP}},
		{name: "scopes", addrs: []loadbalancer.L3n4Addr{scoped(loadbalancer.ScopeExternal), scoped(loadbalancer.ScopeInternal)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRestoreEnv(t)
			warnings := e.recordWarnings()
			for _, addr := range tc.addrs {
				e.seed(addr, aliasID)
			}
			e.restore()

			require.Empty(t, *warnings)
			require.Len(t, e.ops.restoredServiceIDs, len(tc.addrs))
			for _, addr := range tc.addrs {
				require.Equal(t, aliasID, e.ops.restoredServiceIDs[addr], addr)
				require.Equal(t, aliasID, e.update(addr))
			}
		})
	}
}

// TestRestoredServiceIDNodePortExpansion: each address a NodePort or HostPort frontend is
// expanded to has an ID of its own, so restoring them is not a collision.
func TestRestoredServiceIDNodePortExpansion(t *testing.T) {
	e := newRestoreEnv(t)
	wtxn := e.ops.db.WriteTxn(e.nodeAddrs)
	for _, addr := range []string{"10.0.0.3", "10.0.0.4"} {
		_, _, err := e.nodeAddrs.Insert(wtxn, tables.NodeAddress{Addr: netip.MustParseAddr(addr), NodePort: true, Primary: true, DeviceName: "lol0"})
		require.NoError(t, err)
	}
	wtxn.Commit()

	surrogate := func(port uint16) loadbalancer.L3n4Addr { return restoreAddr(loadbalancer.TCP, "0.0.0.0", port) }
	nodePort, hostPort := frontendAt(surrogate(30000)), frontendAt(surrogate(8080))
	nodePort.Type, hostPort.Type = NodePort, HostPort
	ids := map[loadbalancer.L3n4Addr]loadbalancer.ServiceID{}
	for _, fe := range []*loadbalancer.Frontend{nodePort, hostPort} {
		e.updateFrontend(fe)
		for _, ip := range []string{"0.0.0.0", "10.0.0.3", "10.0.0.4"} {
			addr := restoreAddr(loadbalancer.TCP, ip, fe.Address.Port())
			id, found := e.masterID(addr)
			require.True(t, found, addr)
			ids[addr] = id
		}
	}
	require.Len(t, ids, 6)
	require.Len(t, sets.New(slices.Collect(stdmaps.Values(ids))...), 6, "expanded addresses get distinct IDs")

	warnings := e.recordWarnings()
	e.restore()
	require.Empty(t, *warnings)
	require.Equal(t, ids, e.ops.restoredServiceIDs)
}

// TestRestoredServiceIDIPFamilyCollision: a collision in IPv4 does not affect the IPv6
// frontend with the same ID.
func TestRestoredServiceIDIPFamilyCollision(t *testing.T) {
	v4 := restoreAddr(loadbalancer.TCP, "172.18.0.10", 80)
	v4other := restoreAddr(loadbalancer.TCP, "172.18.0.11", 80)
	v6 := restoreAddr(loadbalancer.TCP, "fd00::10", 80)

	// The IPv6 entry is seeded first, as the fake reverse NAT map does not tell the
	// families apart.
	e := newRestoreEnv(t)
	warnings := e.recordWarnings()
	e.seed(v6, aliasID)
	e.seed(v4, aliasID)
	e.seed(v4other, aliasID)
	e.restore()
	require.Len(t, *warnings, 1)
	require.Equal(t, "IPv4", recordAttrs((*warnings)[0])[logfields.Family])
	require.Equal(t, map[loadbalancer.L3n4Addr]loadbalancer.ServiceID{v4other: aliasID, v6: aliasID}, e.ops.restoredServiceIDs)
}

// TestRestoredServiceIDCollisionNotUpdated: the stale entries of a frontend that is not
// updated are pruned, without the ones of the frontend that keeps the ID.
func TestRestoredServiceIDCollisionNotUpdated(t *testing.T) {
	loser := aliasTCP
	owner := restoreAddr(loadbalancer.TCP, "172.18.22.213", 8000)

	newEnv := func(t *testing.T) *restoreEnv {
		e := newRestoreEnv(t)
		e.seed(loser, aliasID)
		e.seed(owner, aliasID)
		e.restore()
		require.NotContains(t, e.ops.restoredServiceIDs, loser)
		return e
	}

	t.Run("loser", func(t *testing.T) {
		e := newEnv(t)
		e.delete(loser) // It is not known yet.
		require.Equal(t, aliasID, e.update(owner))
		e.prune()

		require.False(t, e.hasMaster(loser), "stale master of the loser")
		e.requireOwns(owner, aliasID)
		require.Equal(t, sets.New(owner), e.ops.serviceIDAlloc.idToAddrs[aliasID])
		require.Empty(t, e.ops.restoredServiceIDs)

		e.delete(owner)
		e.prune()
		require.True(t, e.lbmaps.IsEmpty(), "BPF maps after deleting the owner")
	})

	t.Run("owner", func(t *testing.T) {
		e := newEnv(t)
		newID := e.update(loser)
		require.NotEqual(t, aliasID, newID)
		e.prune()

		require.False(t, e.hasMaster(owner), "stale master of the owner")
		_, found := e.revNatAddr(aliasID)
		require.False(t, found, "stale reverse NAT of the owner")
		e.requireOwns(loser, newID)

		e.delete(loser)
		e.prune()
		require.True(t, e.lbmaps.IsEmpty(), "BPF maps after deleting the loser")
		require.Empty(t, e.ops.serviceIDAlloc.idToAddrs)
	})

	// The ID is not given to another frontend when the frontend that keeps it is deleted
	// before the stale entries of the other one, that still have the ID, are pruned.
	t.Run("owner_deleted", func(t *testing.T) {
		e := newEnv(t)
		require.Equal(t, aliasID, e.update(owner))
		e.delete(owner)

		require.False(t, e.freshAllocationsReach(aliasID, 5), "ID reused while the stale entries of the other frontend remain")
		require.True(t, e.hasMaster(loser))

		e.prune()
		require.False(t, e.hasMaster(loser), "stale master of the loser")
		require.True(t, e.freshAllocationsReach(aliasID, 5), "ID not released by Prune")
	})
}

// TestRestoredServiceIDCollisionAffinity: the affinity match of the old ID of a renumbered
// frontend is removed, and the ones of the frontend that keeps the ID are not.
func TestRestoredServiceIDCollisionAffinity(t *testing.T) {
	owner := restoreAddr(loadbalancer.TCP, "172.18.22.213", 8000)

	e := newRestoreEnv(t)
	e.seed(aliasTCP, aliasID)
	e.seed(owner, aliasID)
	// The backend of the loser, and its affinity match with the ID.
	e.seedBackend(restoreAddr(loadbalancer.ANY, "10.1.0.1", 53), 7)
	key := &maps.AffinityMatchKey{BackendID: 7, RevNATID: uint16(aliasID)}
	require.NoError(t, e.lbmaps.UpdateAffinityMatch(key.ToNetwork(), &maps.AffinityMatchValue{}))
	e.restore()

	update := func(addr loadbalancer.L3n4Addr, backend string) loadbalancer.ServiceID {
		return e.updateFrontend(affinityFrontend(addr, activeBackend(addr.Protocol(), backend, addr.Port())))
	}
	loserID := update(aliasTCP, "10.1.0.1")
	require.Equal(t, aliasID, update(owner, "10.2.0.1"))
	e.prune()
	require.Len(t, e.affinityMatches(aliasID), 1, "affinity matches of the owner")
	require.Len(t, e.affinityMatches(loserID), 1, "affinity matches of the loser")

	e.delete(aliasTCP)
	e.delete(owner)
	e.prune()
	require.True(t, e.lbmaps.IsEmpty(), "BPF maps after deleting the frontends")
}

// TestRestoredServiceIDCollisionAffinityTail: the restored service slot of a renumbered
// frontend that is not rewritten, as its backend is in maintenance and has no slot, does
// not keep the affinity match of the old ID.
func TestRestoredServiceIDCollisionAffinityTail(t *testing.T) {
	owner := restoreAddr(loadbalancer.TCP, "172.18.22.213", 8000)
	kept := activeBackend(loadbalancer.TCP, "10.1.0.2", 53)
	maintenance := restoreAddr(loadbalancer.TCP, "10.1.0.1", 53)

	e := newRestoreEnv(t)
	e.seed(aliasTCP, aliasID)
	e.seed(owner, aliasID) // The reverse NAT entry is the one of the owner.
	e.seedBackend(kept.Address, 8)
	e.seedBackend(maintenance, 7)
	// The loser had two backends, the one in maintenance has the second slot.
	e.seedSlots(aliasTCP, aliasID, 8, 7)
	match := &maps.AffinityMatchKey{BackendID: 7, RevNATID: uint16(aliasID)}
	require.NoError(t, e.lbmaps.UpdateAffinityMatch(match.ToNetwork(), &maps.AffinityMatchValue{}))
	e.restore()

	loserID := e.updateFrontend(affinityFrontend(aliasTCP,
		kept,
		newTestBackend(maintenance, loadbalancer.BackendStateMaintenance)))
	require.NotEqual(t, aliasID, loserID)
	winnerBackend := activeBackend(loadbalancer.TCP, "10.2.0.1", 8000)
	require.Equal(t, aliasID, e.updateFrontend(affinityFrontend(owner, winnerBackend)))
	e.prune()

	// The slot of the maintenance backend is not rewritten, it keeps the old ID.
	require.Equal(t, []loadbalancer.BackendID{e.ops.backendStates[winnerBackend.Address].id}, e.affinityMatches(aliasID), "affinity matches of the owner")
}

// TestRestoredServiceIDAffinityStaleSlot: the affinity match of a restored backend slot
// that the frontend does not use anymore is pruned with the slot.
func TestRestoredServiceIDAffinityStaleSlot(t *testing.T) {
	kept := activeBackend(loadbalancer.TCP, "10.1.0.2", 53)
	e := newRestoreEnv(t)
	e.seed(aliasTCP, aliasID)
	e.seedBackend(kept.Address, 8)
	e.seedBackend(restoreAddr(loadbalancer.TCP, "10.1.0.1", 53), 7)
	e.seedSlots(aliasTCP, aliasID, 8, 7)
	for _, beID := range []loadbalancer.BackendID{7, 8} {
		match := &maps.AffinityMatchKey{BackendID: beID, RevNATID: uint16(aliasID)}
		require.NoError(t, e.lbmaps.UpdateAffinityMatch(match.ToNetwork(), &maps.AffinityMatchValue{}))
	}
	e.restore()

	require.Equal(t, aliasID, e.updateFrontend(affinityFrontend(aliasTCP, kept)))
	e.prune()
	require.Equal(t, []loadbalancer.BackendID{8}, e.affinityMatches(aliasID))
}

// TestAffinityMatchAfterPartialUpdate: the affinity matches that a frontend programmed are
// not pruned when its update failed at the end, before its references were updated. It is
// here to use the helpers of the tests of the restored IDs.
func TestAffinityMatchAfterPartialUpdate(t *testing.T) {
	e := newRestoreEnv(t)
	addr := restoreAddr(loadbalancer.TCP, "172.18.0.20", 80)
	frontend := func(ips ...string) *loadbalancer.Frontend {
		var bes []loadbalancer.Backend
		for _, ip := range ips {
			bes = append(bes, activeBackend(loadbalancer.TCP, ip, 8080))
		}
		return affinityFrontend(addr, bes...)
	}
	id := e.updateFrontend(frontend("10.1.0.1", "10.1.0.2", "10.1.0.3"))
	require.Len(t, e.affinityMatches(id), 3)

	// The old slot that is not needed anymore cannot be deleted, after the new slots,
	// matches and master were written.
	e.lbmaps.failDeleteService = true
	require.Error(t, e.ops.Update(t.Context(), e.ops.db.ReadTxn(), 0, frontend("10.2.0.1", "10.2.0.2")))
	e.lbmaps.failDeleteService = false
	matches := e.affinityMatches(id)
	require.Len(t, matches, 2)

	e.prune()
	require.ElementsMatch(t, matches, e.affinityMatches(id), "affinity matches of the live service were pruned")

	// The matches are not pruned either if the service map cannot be dumped.
	e.lbmaps.failDumpService = true
	require.Error(t, e.ops.Prune(t.Context(), nil, nil))
	e.lbmaps.failDumpService = false
	require.ElementsMatch(t, matches, e.affinityMatches(id), "affinity matches of the live service were pruned")
}

// TestRestoredServiceIDCollisionWrap: a restored ID next to the maximum makes the
// allocator wrap around. Neither the ID of the frontend that keeps the colliding ID
// nor the new ID of the other frontend are given to other frontends.
func TestRestoredServiceIDCollisionWrap(t *testing.T) {
	highID := maxSetOfServiceID - 1
	high := restoreAddr(loadbalancer.TCP, "172.18.5.5", 8080)
	owner := restoreAddr(loadbalancer.TCP, "172.18.22.213", 8000)

	e := newRestoreEnv(t)
	e.seed(aliasTCP, aliasID)
	e.seed(owner, aliasID)
	e.seed(high, highID)
	e.restore()

	loserID := e.update(aliasTCP)
	require.NotContains(t, []loadbalancer.ServiceID{aliasID, highID}, loserID)
	require.Equal(t, aliasID, e.update(owner))
	require.Equal(t, highID, e.update(high))
	require.False(t, e.freshAllocationsReach(aliasID, 60), "ID of the owner reused")
	require.False(t, e.freshAllocationsReach(loserID, 60), "new ID of the loser reused")
}

// TestRestoredServiceIDCollisionWarnings: a warning is logged for each restored ID with
// different frontends, also when there are more than the rate limit of the logger.
func TestRestoredServiceIDCollisionWarnings(t *testing.T) {
	e := newRestoreEnv(t)
	warnings := e.recordWarnings()
	const collisions = logRateBurst + 5
	for i := 1; i <= collisions; i++ {
		e.seed(restoreAddr(loadbalancer.TCP, fmt.Sprintf("10.1.%d.1", i), 80), loadbalancer.ServiceID(i))
		e.seed(restoreAddr(loadbalancer.TCP, fmt.Sprintf("10.1.%d.2", i), 80), loadbalancer.ServiceID(i))
	}
	e.restore()

	require.Len(t, *warnings, collisions)
	seen := sets.New[loadbalancer.ServiceID]()
	for _, record := range *warnings {
		attrs := recordAttrs(record)
		id, ok := attrs[logfields.ID].(loadbalancer.ServiceID)
		require.True(t, ok)
		seen.Insert(id)
		// The reverse NAT entry is the last one that was seeded.
		require.Equal(t, fmt.Sprintf("10.1.%d.2:80", id), attrs[logfields.Frontend])
		require.Equal(t, []string{fmt.Sprintf("10.1.%d.1:80/TCP", id)}, attrs[logfields.Addresses])
		require.Equal(t, "reverse NAT entry", attrs[logfields.Reason])
	}
	require.Len(t, seen, collisions, "warnings of different IDs")
}
