// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var (
	svcNamespace = "test-namespace"
	svcName1     = "foo-service"
	svcName2     = "bar-service"

	ipAddrAny  = "0.0.0.0"
	ipAddr101  = "10.244.255.101"
	ip6AddrAny = "::"
	ip6Addr101 = "fd00:10:244::101"

	fooSvcKey  = resource.Key{Name: svcName1, Namespace: svcNamespace}
	fooSvcName = loadbalancer.NewServiceName(fooSvcKey.Namespace, fooSvcKey.Name)
	fooSvc     = &loadbalancer.Service{
		Name:             fooSvcName,
		Source:           source.Kubernetes,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	fooSvcWithForwardAction = &loadbalancer.Service{
		Name:                   fooSvcName,
		Source:                 source.Kubernetes,
		ExtTrafficPolicy:       loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:       loadbalancer.SVCTrafficPolicyCluster,
		UnsupportedProtoAction: annotation.UnsupportedProtoActionForward,
	}

	barSvcKey            = resource.Key{Name: svcName2, Namespace: svcNamespace}
	barSvcName           = loadbalancer.NewServiceName(barSvcKey.Namespace, barSvcKey.Name)
	barSvcWithDropAction = &loadbalancer.Service{
		Name:                   barSvcName,
		Source:                 source.Kubernetes,
		ExtTrafficPolicy:       loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:       loadbalancer.SVCTrafficPolicyCluster,
		UnsupportedProtoAction: annotation.UnsupportedProtoActionDrop,
	}
)

func newFrontend(
	tb testing.TB,
	svc *loadbalancer.Service,
	svcType loadbalancer.SVCType,
	addr string,
	scope uint8,
) *loadbalancer.Frontend {
	tb.Helper()

	svcAddr := loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster(addr), 80, scope)
	return &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			ServiceName: svc.Name,
			Address:     svcAddr,
			Type:        svcType,
		},
		Service: svc,
	}
}

func TestRegisterLoadBalanceFrontendWatcher(t *testing.T) {
	tests := []struct {
		name          string
		defaultAction string
		expected      bool
	}{
		{
			name:          "default-upa-forward",
			defaultAction: loadbalancer.LBUnsupportedProtoActionForward,
			expected:      false,
		},
		{
			name:          "default-upa-drop",
			defaultAction: loadbalancer.LBUnsupportedProtoActionDrop,
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo))
			s := setupIPCacheTestSuite(t)
			ipc := s.IPIdentityCache

			lbconfig := loadbalancer.DefaultConfig
			lbconfig.LBUnsupportedProtoAction = tt.defaultAction

			registerWatcher := func(watcher loadBalancerFrontendWatcher, jobGroup job.Group) error {
				err := RegisterLoadBalanceFrontendWatcher(watcher, jobGroup)
				assert.NotNil(t, watcher.ipcache)
				assert.NotNil(t, watcher.db)
				assert.Equal(t, tt.expected, watcher.dropByDefault)
				return err
			}

			h := hive.New(
				node.LocalNodeStoreTestCell,
				cell.Provide(
					loadbalancer.NewFrontendsTable,
					statedb.RWTable[*loadbalancer.Frontend].ToTable,
					func() loadbalancer.Config { return lbconfig },
					func() *option.DaemonConfig { return &option.DaemonConfig{} },
					tables.NewNodeAddressTable,
					statedb.RWTable[tables.NodeAddress].ToTable,
					source.NewSources,
					func() *IPCache { return ipc },
					NewLoadBalancerFrontendWatcher,
				),
				cell.Invoke(
					registerWatcher,
				),
			)
			require.NoError(t, h.Start(log, ctx))
			t.Cleanup(func() {
				h.Stop(log, ctx)
			})
		})
	}
}

func TestIsCandidateUnroutable(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		scope     uint8
		candidate bool
	}{
		// Real IP addresses
		{
			name:      "ipv4-101-internal",
			addr:      ipAddr101,
			scope:     loadbalancer.ScopeInternal,
			candidate: false,
		},
		{
			name:      "ipv4-101-external",
			addr:      ipAddr101,
			scope:     loadbalancer.ScopeExternal,
			candidate: true,
		},
		{
			name:      "ipv6-101-internal",
			addr:      ip6Addr101,
			scope:     loadbalancer.ScopeInternal,
			candidate: false,
		},
		{
			name:      "ipv6-101-external",
			addr:      ip6Addr101,
			scope:     loadbalancer.ScopeExternal,
			candidate: true,
		},

		// INADDR_ANY / IN6ADDR_ANY
		{
			name:      "ipv4-any-internal",
			addr:      ipAddrAny,
			scope:     loadbalancer.ScopeInternal,
			candidate: false,
		},
		{
			name:      "ipv4-any-external",
			addr:      ipAddrAny,
			scope:     loadbalancer.ScopeExternal,
			candidate: false,
		},
		{
			name:      "ipv6-any-internal",
			addr:      ip6AddrAny,
			scope:     loadbalancer.ScopeInternal,
			candidate: false,
		},
		{
			name:      "ipv6-any-external",
			addr:      ip6AddrAny,
			scope:     loadbalancer.ScopeExternal,
			candidate: false,
		},
	}

	validCandidateTypes := []loadbalancer.SVCType{
		loadbalancer.SVCTypeClusterIP,
		loadbalancer.SVCTypeExternalIPs,
		loadbalancer.SVCTypeLoadBalancer,
	}
	invalidCandidateTypes := []loadbalancer.SVCType{
		loadbalancer.SVCTypeNone,
		loadbalancer.SVCTypeHostPort,
		loadbalancer.SVCTypeNodePort,
		loadbalancer.SVCTypeLocalRedirect,
	}

	watcher := loadBalancerFrontendWatcher{}

	for _, tt := range tests {
		for _, svcType := range validCandidateTypes {
			testName := fmt.Sprintf("candidate-%s-type-%s", tt.name, strings.ToLower(string(svcType)))
			t.Run(testName, func(t *testing.T) {
				frontend := newFrontend(t, fooSvc, svcType, tt.addr, tt.scope)
				assert.Equal(t, tt.candidate, watcher.isCandidateUnroutable(frontend))
			})
		}
		for _, svcType := range invalidCandidateTypes {
			testName := fmt.Sprintf("candidate-%s-type-%s", tt.name, strings.ToLower(string(svcType)))
			t.Run(testName, func(t *testing.T) {
				frontend := newFrontend(t, fooSvc, svcType, tt.addr, tt.scope)
				assert.False(t, watcher.isCandidateUnroutable(frontend))
			})
		}
	}
}

func TestUseUnroutableFlag(t *testing.T) {
	tests := []struct {
		name              string
		defaultAction     annotation.UnsupportedProtoAction
		svc               *loadbalancer.Service
		addr              string
		useUnroutableFlag bool
	}{
		// defaultAction = unspec
		{
			name:              "default-unspec+svc-unspec+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionUnspec,
			svc:               fooSvc,
			addr:              ipAddr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-unspec+svc-unspec+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionUnspec,
			svc:               fooSvc,
			addr:              ip6Addr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-unspec+svc-forward+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionUnspec,
			svc:               fooSvcWithForwardAction,
			addr:              ipAddr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-unspec+svc-forward+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionUnspec,
			svc:               fooSvcWithForwardAction,
			addr:              ip6Addr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-unspec+svc-drop+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionUnspec,
			svc:               barSvcWithDropAction,
			addr:              ipAddr101,
			useUnroutableFlag: true,
		},
		{
			name:              "default-unspec+svc-drop+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionUnspec,
			svc:               barSvcWithDropAction,
			addr:              ip6Addr101,
			useUnroutableFlag: true,
		},
		// defaultAction = forward
		{
			name:              "default-forward+svc-unspec+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionForward,
			svc:               fooSvc,
			addr:              ipAddr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-forward+svc-unspec+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionForward,
			svc:               fooSvc,
			addr:              ip6Addr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-forward+svc-forward+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionForward,
			svc:               fooSvcWithForwardAction,
			addr:              ipAddr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-forward+svc-forward+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionForward,
			svc:               fooSvcWithForwardAction,
			addr:              ip6Addr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-forward+svc-drop+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionForward,
			svc:               barSvcWithDropAction,
			addr:              ipAddr101,
			useUnroutableFlag: true,
		},
		{
			name:              "default-forward+svc-drop+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionForward,
			svc:               barSvcWithDropAction,
			addr:              ip6Addr101,
			useUnroutableFlag: true,
		},
		// defaultAction = drop
		{
			name:              "default-drop+svc-unspec+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionDrop,
			svc:               fooSvc,
			addr:              ipAddr101,
			useUnroutableFlag: true,
		},
		{
			name:              "default-drop+svc-unspec+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionDrop,
			svc:               fooSvc,
			addr:              ip6Addr101,
			useUnroutableFlag: true,
		},
		{
			name:              "default-drop+svc-forward+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionDrop,
			svc:               fooSvcWithForwardAction,
			addr:              ipAddr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-drop+svc-forward+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionDrop,
			svc:               fooSvcWithForwardAction,
			addr:              ip6Addr101,
			useUnroutableFlag: false,
		},
		{
			name:              "default-drop+svc-drop+ipv4",
			defaultAction:     annotation.UnsupportedProtoActionDrop,
			svc:               barSvcWithDropAction,
			addr:              ipAddr101,
			useUnroutableFlag: true,
		},
		{
			name:              "default-drop+svc-drop+ipv6",
			defaultAction:     annotation.UnsupportedProtoActionDrop,
			svc:               barSvcWithDropAction,
			addr:              ip6Addr101,
			useUnroutableFlag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := loadBalancerFrontendWatcher{
				dropByDefault: tt.defaultAction == annotation.UnsupportedProtoActionDrop,
			}
			frontend := newFrontend(t, tt.svc, loadbalancer.SVCTypeLoadBalancer, tt.addr,
				loadbalancer.ScopeExternal)
			assert.Equal(t, tt.useUnroutableFlag, watcher.useUnroutableFlag(frontend))
		})
	}
}

type testFrontendChangeState struct {
	ctx      context.Context
	log      *slog.Logger
	s        *IPCacheTestSuite
	watcher  loadBalancerFrontendWatcher
	db       *statedb.DB
	svcTable statedb.RWTable[*loadbalancer.Service]
	feTable  statedb.RWTable[*loadbalancer.Frontend]
}

func (state *testFrontendChangeState) insertFrontend(tb testing.TB, svc *loadbalancer.Service, fes ...*loadbalancer.Frontend) {
	tb.Helper()

	wtxn := state.db.WriteTxn(state.svcTable, state.feTable)

	_, hadOld, err := state.svcTable.Insert(wtxn, svc)
	require.NoError(tb, err)
	require.False(tb, hadOld)

	for _, fe := range fes {
		_, hadOld, err := state.feTable.Insert(wtxn, fe)
		require.NoError(tb, err)
		require.False(tb, hadOld)
	}

	wtxn.Commit()
}

func (state *testFrontendChangeState) deleteFrontend(tb testing.TB, svc *loadbalancer.Service, fes ...*loadbalancer.Frontend) {
	tb.Helper()

	wtxn := state.db.WriteTxn(state.svcTable, state.feTable)
	for _, fe := range fes {
		_, hadOld, err := state.feTable.Delete(wtxn, fe)
		require.NoError(tb, err)
		require.True(tb, hadOld)
	}

	_, hadOld, err := state.svcTable.Delete(wtxn, svc)
	require.NoError(tb, err)
	require.True(tb, hadOld)

	wtxn.Commit()
}

func (state *testFrontendChangeState) onFrontendChange(tb testing.TB, fe *loadbalancer.Frontend, deleted bool) {
	tb.Helper()

	// Call the onFrontendChange event handler
	err := state.watcher.onFrontendChange(state.ctx, statedb.Change[*loadbalancer.Frontend]{
		Deleted: deleted,
		Object:  fe,
	})
	require.NoError(tb, err)
}

func (state *testFrontendChangeState) assertAddressIdentity(
	tb testing.TB,
	addr string,
	present bool,
) {
	tb.Helper()

	prefix := cmtypes.MustParseAddrCluster(addr).AsPrefixCluster()
	resourceInfo := state.s.IPIdentityCache.metadata.get(prefix)

	if present {
		// Metadata should exist
		require.NotNil(tb, resourceInfo)

		// The resource should have either world-ipv4 or world-ipv6 labels.
		var worldLabels labels.Labels
		if prefix.AddrCluster().Is6() {
			worldLabels = labels.NewLabelsFromSortedList("reserved:world-ipv6")
		} else {
			worldLabels = labels.NewLabelsFromSortedList("reserved:world-ipv4")
		}
		resourceLabels := resourceInfo.ToLabels()
		require.Equal(tb, worldLabels, resourceLabels)

		// Endpoint flags should be valid
		require.True(tb, resourceInfo.endpointFlags.IsValid())

		// FlagUnroutable should be set
		flags := resourceInfo.endpointFlags.Uint8()
		require.NotEqual(tb, 0, flags&ipcacheTypes.FlagUnroutable)
	} else {
		// Metadata should not exist
		require.Nil(tb, resourceInfo)
	}
}

// This test verifies the watcher.onFrontendChange() logic in a synchronous
// fashion. As such, the LoadBalancerFrontendWatcher is provided to the cell is
// not registered, and the test calls testFrontendChangeState.onFrontendChange()
// which waits on IPCache synchronisation so we can assert state.
func TestOnFrontendChange_Sync(t *testing.T) {
	ctx := t.Context()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	s := setupIPCacheTestSuite(t)
	ipc := s.IPIdentityCache
	lbconfig := loadbalancer.DefaultConfig

	state := &testFrontendChangeState{
		ctx: ctx,
		log: log,
		s:   s,
	}

	h := hive.New(
		node.LocalNodeStoreTestCell,
		cell.Provide(
			func() loadbalancer.Config { return lbconfig },
			loadbalancer.NewFrontendsTable,
			statedb.RWTable[*loadbalancer.Frontend].ToTable,
			loadbalancer.NewServicesTable,
			statedb.RWTable[*loadbalancer.Service].ToTable,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4: true,
					EnableIPv6: true,
				}
			},
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			source.NewSources,
			func() *IPCache { return ipc },
			NewLoadBalancerFrontendWatcher,
		),
		cell.Invoke(
			func(_ loadBalancerFrontendWatcher) {},

			// Capture stateDB variables so we can author transactions
			// and test that we capture the right events
			func(watcher loadBalancerFrontendWatcher, db *statedb.DB, svcTable statedb.RWTable[*loadbalancer.Service], feTable statedb.RWTable[*loadbalancer.Frontend]) {
				state.watcher = watcher
				state.db = db
				state.svcTable = svcTable
				state.feTable = feTable
			},
		),
	)
	require.NoError(t, h.Start(log, ctx))
	t.Cleanup(func() {
		h.Stop(log, ctx)
	})

	require.NotNil(t, state.watcher.ipcache)
	require.NotNil(t, state.db)
	require.NotNil(t, state.svcTable)
	require.NotNil(t, state.feTable)

	// Create frontend for foo-service with Forward action. This should
	// result in no entry being added into the IPCache.
	fooFrontendIPv4 := newFrontend(t, fooSvcWithForwardAction, loadbalancer.SVCTypeLoadBalancer,
		ipAddr101, loadbalancer.ScopeExternal)
	state.insertFrontend(t, fooSvcWithForwardAction, fooFrontendIPv4)
	state.onFrontendChange(t, fooFrontendIPv4, false)
	state.assertAddressIdentity(t, ipAddr101, false)

	// Create frontend for bar-service with Drop action. This should result
	// in an entry being added into the IPCache.
	barFrontendIPv6 := newFrontend(t, barSvcWithDropAction, loadbalancer.SVCTypeLoadBalancer,
		ip6Addr101, loadbalancer.ScopeExternal)
	state.insertFrontend(t, barSvcWithDropAction, barFrontendIPv6)
	state.onFrontendChange(t, barFrontendIPv6, false)
	state.assertAddressIdentity(t, ip6Addr101, true)

	// Now delete foo-service
	state.deleteFrontend(t, fooSvcWithForwardAction, fooFrontendIPv4)
	state.onFrontendChange(t, fooFrontendIPv4, true)
	state.assertAddressIdentity(t, ipAddr101, false)

	// Now delete bar-service
	state.deleteFrontend(t, barSvcWithDropAction, barFrontendIPv6)
	state.onFrontendChange(t, barFrontendIPv6, true)
	state.assertAddressIdentity(t, ip6Addr101, false)
}

// This test verifies the watcher.onFrontendChange() logic in an asynchronous
// fashion. As such, the LoadBalancerFrontendWatcher is provided to the cell and
// properly registered to execute on changes. This test aims to test the overall
// lifecycle of the watcher is behaving properly.
func TestOnFrontendChange_Async(t *testing.T) {
	ctx := context.Background()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	s := setupIPCacheTestSuite(t)
	ipc := s.IPIdentityCache
	lbconfig := loadbalancer.DefaultConfig

	state := &testFrontendChangeState{
		ctx: ctx,
		log: log,
		s:   s,
	}

	h := hive.New(
		node.LocalNodeStoreTestCell,
		cell.Provide(
			func() loadbalancer.Config { return lbconfig },
			loadbalancer.NewFrontendsTable,
			statedb.RWTable[*loadbalancer.Frontend].ToTable,
			loadbalancer.NewServicesTable,
			statedb.RWTable[*loadbalancer.Service].ToTable,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableIPv4: true,
					EnableIPv6: true,
				}
			},
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			source.NewSources,
			func() *IPCache { return ipc },
			NewLoadBalancerFrontendWatcher,
		),
		cell.Invoke(
			RegisterLoadBalanceFrontendWatcher,

			// Capture stateDB variables so we can author transactions
			// and test that we capture the right events
			func(watcher loadBalancerFrontendWatcher, db *statedb.DB, svcTable statedb.RWTable[*loadbalancer.Service], feTable statedb.RWTable[*loadbalancer.Frontend]) {
				state.watcher = watcher
				state.db = db
				state.svcTable = svcTable
				state.feTable = feTable
			},
		),
	)
	require.NoError(t, h.Start(log, ctx))
	t.Cleanup(func() {
		h.Stop(log, ctx)
	})

	require.NotNil(t, state.watcher.ipcache)
	require.NotNil(t, state.db)
	require.NotNil(t, state.svcTable)
	require.NotNil(t, state.feTable)

	// Create frontend for foo-service with Forward action. This should
	// result in no entry being added into the IPCache.
	fooFrontendIPv4 := newFrontend(t, fooSvcWithForwardAction, loadbalancer.SVCTypeLoadBalancer,
		ipAddr101, loadbalancer.ScopeExternal)
	state.insertFrontend(t, fooSvcWithForwardAction, fooFrontendIPv4)

	// Create frontend for bar-service with Drop action. This should result
	// in an entry being added into the IPCache.
	barFrontendIPv6 := newFrontend(t, barSvcWithDropAction, loadbalancer.SVCTypeLoadBalancer,
		ip6Addr101, loadbalancer.ScopeExternal)
	state.insertFrontend(t, barSvcWithDropAction, barFrontendIPv6)

	// Wait for events to process
	time.Sleep(time.Second)

	// Assert expected state
	state.assertAddressIdentity(t, ipAddr101, false)
	state.assertAddressIdentity(t, ip6Addr101, true)

	// Now delete foo-service
	state.deleteFrontend(t, fooSvcWithForwardAction, fooFrontendIPv4)

	// Now delete bar-service
	state.deleteFrontend(t, barSvcWithDropAction, barFrontendIPv6)

	// Wait for events to process
	time.Sleep(time.Second)

	// Assert expected state
	state.assertAddressIdentity(t, ipAddr101, false)
	state.assertAddressIdentity(t, ip6Addr101, false)
}
