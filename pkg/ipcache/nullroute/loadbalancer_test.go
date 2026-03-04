// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nullroute

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

var (
	svcNamespace = "test-namespace"
	svcName1     = "foo-service"
	svcName2     = "bar-service"

	ipAddrAny  = "0.0.0.0"
	ipAddr101  = "10.244.255.101"
	ip6AddrAny = "::"
	ip6Addr101 = "fd00:10:244::101"

	bgpLoadBalancerClass   = cilium_api_v2alpha1.BGPLoadBalancerClass
	l2LoadBalancerClass    = cilium_api_v2alpha1.L2AnnounceLoadBalancerClass
	otherLoadBalancerClass = "other"

	defaultLBIPAMExtConfig = loadbalancer.ExternalConfig{
		DefaultLBServiceIPAM: lbipamconfig.DefaultLBClassLBIPAM,
	}
	defaultNodeIPAMExtConfig = loadbalancer.ExternalConfig{
		DefaultLBServiceIPAM: lbipamconfig.DefaultLBClassNodeIPAM,
	}

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
	fooSvcLBClassBGP = &loadbalancer.Service{
		Name:              fooSvcName,
		Source:            source.Kubernetes,
		ExtTrafficPolicy:  loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:  loadbalancer.SVCTrafficPolicyCluster,
		LoadBalancerClass: &bgpLoadBalancerClass,
	}
	fooSvcLBClassL2Announce = &loadbalancer.Service{
		Name:              fooSvcName,
		Source:            source.Kubernetes,
		ExtTrafficPolicy:  loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:  loadbalancer.SVCTrafficPolicyCluster,
		LoadBalancerClass: &l2LoadBalancerClass,
	}
	fooSvcLBClassOther = &loadbalancer.Service{
		Name:              fooSvcName,
		Source:            source.Kubernetes,
		ExtTrafficPolicy:  loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy:  loadbalancer.SVCTrafficPolicyCluster,
		LoadBalancerClass: &otherLoadBalancerClass,
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

type mockIdentityUpdater struct{}

func (mockIdentityUpdater) UpdateIdentities(identity.IdentityMap, identity.IdentityMap) <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func newIPCache(tb testing.TB, log *slog.Logger) *ipcache.IPCache {
	tb.Helper()

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           tb.Context(),
		Logger:            log,
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		IdentityUpdater:   mockIdentityUpdater{},
	})
	tb.Cleanup(func() {
		ipc.Shutdown()
	})

	return ipc
}

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

func expectedResourceID(fe *loadbalancer.Frontend) ipcacheTypes.ResourceID {
	return ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindService,
		fe.Service.Name.Namespace(),
		fe.Address.StringWithProtocolDelimited(":"),
	)
}

func expectedWorldLabels(addr string) labels.Labels {
	lbls := make(labels.Labels, 1)
	lbls.AddWorldLabel(cmtypes.MustParseAddrCluster(addr).Addr())
	return lbls
}

// Mock metadata recorder used to assert the direct outputs of onFrontendChange().
type metadataRecord struct {
	prefix   cmtypes.PrefixCluster
	source   source.Source
	resource ipcacheTypes.ResourceID
	labels   labels.Labels
	flags    ipcacheTypes.EndpointFlags
}

type mockMetadataMutator struct {
	upserts []metadataRecord
	removes []metadataRecord
}

func (m *mockMetadataMutator) UpsertMetadata(
	prefix cmtypes.PrefixCluster,
	src source.Source,
	resource ipcacheTypes.ResourceID,
	aux ...ipcache.IPMetadata,
) {
	m.upserts = append(m.upserts, newMetadataRecord(prefix, src, resource, aux...))
}

func (m *mockMetadataMutator) RemoveMetadata(
	prefix cmtypes.PrefixCluster,
	resource ipcacheTypes.ResourceID,
	aux ...ipcache.IPMetadata,
) {
	m.removes = append(m.removes, newMetadataRecord(prefix, source.Unspec, resource, aux...))
}

func newMetadataRecord(
	prefix cmtypes.PrefixCluster,
	src source.Source,
	resource ipcacheTypes.ResourceID,
	aux ...ipcache.IPMetadata,
) metadataRecord {
	record := metadataRecord{
		prefix:   prefix,
		source:   src,
		resource: resource,
	}
	for _, meta := range aux {
		switch v := meta.(type) {
		case labels.Labels:
			record.labels = labels.NewFrom(v)
		case ipcacheTypes.EndpointFlags:
			record.flags = v
		}
	}
	return record
}

// StateDB and listener fixtures used by the end-to-end watcher test.
type frontendWatcherTestState struct {
	db       *statedb.DB
	svcTable statedb.RWTable[*loadbalancer.Service]
	feTable  statedb.RWTable[*loadbalancer.Frontend]
}

func (state *frontendWatcherTestState) insertFrontend(tb testing.TB, svc *loadbalancer.Service, fes ...*loadbalancer.Frontend) {
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

func (state *frontendWatcherTestState) deleteFrontend(tb testing.TB, svc *loadbalancer.Service, fes ...*loadbalancer.Frontend) {
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

type listenerEvent struct {
	modType       ipcache.CacheModification
	prefix        cmtypes.PrefixCluster
	endpointFlags uint8
}

type recordingListener struct {
	events chan listenerEvent
}

func newRecordingListener() *recordingListener {
	return &recordingListener{
		events: make(chan listenerEvent, 16),
	}
}

func (l *recordingListener) OnIPIdentityCacheChange(
	modType ipcache.CacheModification,
	cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP,
	oldID *ipcache.Identity,
	newID ipcache.Identity,
	encryptKey uint8,
	k8sMeta *ipcache.K8sMetadata,
	endpointFlags uint8,
) {
	l.events <- listenerEvent{
		modType:       modType,
		prefix:        cidrCluster,
		endpointFlags: endpointFlags,
	}
}

func (l *recordingListener) waitFor(
	tb testing.TB,
	match func(listenerEvent) bool,
) listenerEvent {
	tb.Helper()

	ctx, cancel := context.WithTimeout(tb.Context(), 5*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			tb.Fatalf("timed out waiting for matching ipcache listener event")
		case event := <-l.events:
			if match(event) {
				return event
			}
		}
	}
}

func TestNewLoadBalancerFrontendWatcher(t *testing.T) {
	tests := []struct {
		name          string
		defaultAction string
		expected      bool
		extConfig     loadbalancer.ExternalConfig
	}{
		{
			name:          "default-upa-forward+default-lbipam",
			defaultAction: loadbalancer.LBUnsupportedProtoActionForward,
			expected:      false,
			extConfig:     defaultLBIPAMExtConfig,
		},
		{
			name:          "default-upa-drop+default-lbipam",
			defaultAction: loadbalancer.LBUnsupportedProtoActionDrop,
			expected:      true,
			extConfig:     defaultLBIPAMExtConfig,
		},
		{
			name:          "default-upa-forward+default-nodeipam",
			defaultAction: loadbalancer.LBUnsupportedProtoActionForward,
			expected:      false,
			extConfig:     defaultNodeIPAMExtConfig,
		},
		{
			name:          "default-upa-drop+default-nodeipam",
			defaultAction: loadbalancer.LBUnsupportedProtoActionDrop,
			expected:      true,
			extConfig:     defaultNodeIPAMExtConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo))
			ipc := newIPCache(t, log)
			db := statedb.New()

			lbConfig := loadbalancer.DefaultConfig
			lbConfig.LBUnsupportedProtoAction = tt.defaultAction
			frontends, err := loadbalancer.NewFrontendsTable(lbConfig, db)
			require.NoError(t, err)

			watcher := newLoadBalancerFrontendWatcher(loadBalancerFrontendWatcherParams{
				IPCache:   ipc,
				DB:        db,
				Frontends: frontends,
				LBConfig:  lbConfig,
				ExtConfig: tt.extConfig,
			})

			assert.Same(t, ipc, watcher.metadata)
			assert.Same(t, db, watcher.db)
			assert.Equal(t, frontends, watcher.frontends)
			assert.Equal(t, tt.expected, watcher.dropByDefault)
			assert.Equal(t, tt.extConfig.DefaultLBServiceIPAM, watcher.defaultLBServiceIPAM)
		})
	}
}

func TestIsNullRouteCandidate(t *testing.T) {
	type testCase struct {
		name        string
		svcType     loadbalancer.SVCType
		addr        string
		scope       uint8
		service     *loadbalancer.Service
		extConfig   loadbalancer.ExternalConfig
		isCandidate bool
	}

	tests := []testCase{
		{
			name:        "clusterip-ipv4-101-internal",
			svcType:     loadbalancer.SVCTypeClusterIP,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeInternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "clusterip-ipv4-101-external-default-lbipam",
			svcType:     loadbalancer.SVCTypeClusterIP,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			extConfig:   defaultLBIPAMExtConfig,
			isCandidate: true,
		},
		{
			name:        "loadbalancer-ipv6-101-internal",
			svcType:     loadbalancer.SVCTypeLoadBalancer,
			addr:        ip6Addr101,
			scope:       loadbalancer.ScopeInternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "loadbalancer-ipv6-101-external-default-lbipam",
			svcType:     loadbalancer.SVCTypeLoadBalancer,
			addr:        ip6Addr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			extConfig:   defaultLBIPAMExtConfig,
			isCandidate: true,
		},
		{
			name:        "externalips-ipv4-any-internal",
			svcType:     loadbalancer.SVCTypeExternalIPs,
			addr:        ipAddrAny,
			scope:       loadbalancer.ScopeInternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "externalips-ipv4-any-external",
			svcType:     loadbalancer.SVCTypeExternalIPs,
			addr:        ipAddrAny,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "externalips-ipv6-any-internal",
			svcType:     loadbalancer.SVCTypeExternalIPs,
			addr:        ip6AddrAny,
			scope:       loadbalancer.ScopeInternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "externalips-ipv6-any-external",
			svcType:     loadbalancer.SVCTypeExternalIPs,
			addr:        ip6AddrAny,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "clusterip-external-managed-bgp-class",
			svcType:     loadbalancer.SVCTypeClusterIP,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvcLBClassBGP,
			isCandidate: true,
		},
		{
			name:        "loadbalancer-external-managed-l2-class",
			svcType:     loadbalancer.SVCTypeLoadBalancer,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvcLBClassL2Announce,
			isCandidate: true,
		},
		{
			name:        "clusterip-external-unmanaged-class",
			svcType:     loadbalancer.SVCTypeClusterIP,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvcLBClassOther,
			isCandidate: false,
		},
		{
			name:        "loadbalancer-external-default-nodeipam",
			svcType:     loadbalancer.SVCTypeLoadBalancer,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			extConfig:   defaultNodeIPAMExtConfig,
			isCandidate: false,
		},
		{
			name:        "externalips-external-managed-bgp-class",
			svcType:     loadbalancer.SVCTypeExternalIPs,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvcLBClassBGP,
			isCandidate: true,
		},
		{
			name:        "externalips-external-default-nodeipam",
			svcType:     loadbalancer.SVCTypeExternalIPs,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			extConfig:   defaultNodeIPAMExtConfig,
			isCandidate: true,
		},
		{
			name:        "none-external",
			svcType:     loadbalancer.SVCTypeNone,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "hostport-external",
			svcType:     loadbalancer.SVCTypeHostPort,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "nodeport-external",
			svcType:     loadbalancer.SVCTypeNodePort,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			isCandidate: false,
		},
		{
			name:        "localredirect-external",
			svcType:     loadbalancer.SVCTypeLocalRedirect,
			addr:        ipAddr101,
			scope:       loadbalancer.ScopeExternal,
			service:     fooSvc,
			isCandidate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := loadBalancerFrontendWatcher{defaultLBServiceIPAM: tt.extConfig.DefaultLBServiceIPAM}
			frontend := newFrontend(t, tt.service, tt.svcType, tt.addr, tt.scope)
			assert.Equal(t, tt.isCandidate, watcher.isNullRouteCandidate(frontend))
		})
	}
}

func TestUseNullRouteFlag(t *testing.T) {
	tests := []struct {
		name          string
		defaultAction annotation.UnsupportedProtoAction
		svc           *loadbalancer.Service
		addr          string
		shouldUseFlag bool
	}{
		{
			name:          "default-unspec+svc-unspec+ipv4",
			defaultAction: annotation.UnsupportedProtoActionUnspec,
			svc:           fooSvc,
			addr:          ipAddr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-unspec+svc-unspec+ipv6",
			defaultAction: annotation.UnsupportedProtoActionUnspec,
			svc:           fooSvc,
			addr:          ip6Addr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-unspec+svc-forward+ipv4",
			defaultAction: annotation.UnsupportedProtoActionUnspec,
			svc:           fooSvcWithForwardAction,
			addr:          ipAddr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-unspec+svc-forward+ipv6",
			defaultAction: annotation.UnsupportedProtoActionUnspec,
			svc:           fooSvcWithForwardAction,
			addr:          ip6Addr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-unspec+svc-drop+ipv4",
			defaultAction: annotation.UnsupportedProtoActionUnspec,
			svc:           barSvcWithDropAction,
			addr:          ipAddr101,
			shouldUseFlag: true,
		},
		{
			name:          "default-unspec+svc-drop+ipv6",
			defaultAction: annotation.UnsupportedProtoActionUnspec,
			svc:           barSvcWithDropAction,
			addr:          ip6Addr101,
			shouldUseFlag: true,
		},
		{
			name:          "default-forward+svc-unspec+ipv4",
			defaultAction: annotation.UnsupportedProtoActionForward,
			svc:           fooSvc,
			addr:          ipAddr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-forward+svc-unspec+ipv6",
			defaultAction: annotation.UnsupportedProtoActionForward,
			svc:           fooSvc,
			addr:          ip6Addr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-forward+svc-forward+ipv4",
			defaultAction: annotation.UnsupportedProtoActionForward,
			svc:           fooSvcWithForwardAction,
			addr:          ipAddr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-forward+svc-forward+ipv6",
			defaultAction: annotation.UnsupportedProtoActionForward,
			svc:           fooSvcWithForwardAction,
			addr:          ip6Addr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-forward+svc-drop+ipv4",
			defaultAction: annotation.UnsupportedProtoActionForward,
			svc:           barSvcWithDropAction,
			addr:          ipAddr101,
			shouldUseFlag: true,
		},
		{
			name:          "default-forward+svc-drop+ipv6",
			defaultAction: annotation.UnsupportedProtoActionForward,
			svc:           barSvcWithDropAction,
			addr:          ip6Addr101,
			shouldUseFlag: true,
		},
		{
			name:          "default-drop+svc-unspec+ipv4",
			defaultAction: annotation.UnsupportedProtoActionDrop,
			svc:           fooSvc,
			addr:          ipAddr101,
			shouldUseFlag: true,
		},
		{
			name:          "default-drop+svc-unspec+ipv6",
			defaultAction: annotation.UnsupportedProtoActionDrop,
			svc:           fooSvc,
			addr:          ip6Addr101,
			shouldUseFlag: true,
		},
		{
			name:          "default-drop+svc-forward+ipv4",
			defaultAction: annotation.UnsupportedProtoActionDrop,
			svc:           fooSvcWithForwardAction,
			addr:          ipAddr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-drop+svc-forward+ipv6",
			defaultAction: annotation.UnsupportedProtoActionDrop,
			svc:           fooSvcWithForwardAction,
			addr:          ip6Addr101,
			shouldUseFlag: false,
		},
		{
			name:          "default-drop+svc-drop+ipv4",
			defaultAction: annotation.UnsupportedProtoActionDrop,
			svc:           barSvcWithDropAction,
			addr:          ipAddr101,
			shouldUseFlag: true,
		},
		{
			name:          "default-drop+svc-drop+ipv6",
			defaultAction: annotation.UnsupportedProtoActionDrop,
			svc:           barSvcWithDropAction,
			addr:          ip6Addr101,
			shouldUseFlag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := loadBalancerFrontendWatcher{
				dropByDefault: tt.defaultAction == annotation.UnsupportedProtoActionDrop,
			}
			frontend := newFrontend(t, tt.svc, loadbalancer.SVCTypeLoadBalancer, tt.addr, loadbalancer.ScopeExternal)
			assert.Equal(t, tt.shouldUseFlag, watcher.useNullRouteFlag(frontend))
		})
	}
}

// TestOnFrontendChangeUpdatesMetadata verifies the translation logic in
// onFrontendChange() directly. This keeps the test focused on which metadata
// mutations are emitted for a given frontend event without depending on IPCache
// internals or asynchronous StateDB/job wiring.
func TestOnFrontendChangeUpdatesMetadata(t *testing.T) {
	watcher := loadBalancerFrontendWatcher{
		metadata:             &mockMetadataMutator{},
		defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
	}
	mutator := watcher.metadata.(*mockMetadataMutator)

	forwardFrontend := newFrontend(t, fooSvcWithForwardAction, loadbalancer.SVCTypeLoadBalancer, ipAddr101, loadbalancer.ScopeExternal)
	dropFrontend := newFrontend(t, barSvcWithDropAction, loadbalancer.SVCTypeLoadBalancer, ip6Addr101, loadbalancer.ScopeExternal)

	require.NoError(t, watcher.onFrontendChange(t.Context(), statedb.Change[*loadbalancer.Frontend]{
		Object: forwardFrontend,
	}))
	require.NoError(t, watcher.onFrontendChange(t.Context(), statedb.Change[*loadbalancer.Frontend]{
		Object: dropFrontend,
	}))
	require.NoError(t, watcher.onFrontendChange(t.Context(), statedb.Change[*loadbalancer.Frontend]{
		Deleted: true,
		Object:  dropFrontend,
	}))

	require.Len(t, mutator.upserts, 1)
	require.Len(t, mutator.removes, 2)

	upsert := mutator.upserts[0]
	assert.Equal(t, dropFrontend.Address.AddrCluster().AsPrefixCluster(), upsert.prefix)
	assert.Equal(t, source.Generated, upsert.source)
	assert.Equal(t, expectedResourceID(dropFrontend), upsert.resource)
	assert.Equal(t, expectedWorldLabels(ip6Addr101), upsert.labels)
	assert.True(t, upsert.flags.IsValid())
	assert.NotZero(t, upsert.flags.Uint8()&ipcacheTypes.FlagNullRoute)

	removeForward := mutator.removes[0]
	assert.Equal(t, forwardFrontend.Address.AddrCluster().AsPrefixCluster(), removeForward.prefix)
	assert.Equal(t, expectedResourceID(forwardFrontend), removeForward.resource)
	assert.Equal(t, expectedWorldLabels(ipAddr101), removeForward.labels)
	assert.False(t, removeForward.flags.IsValid())

	removeDrop := mutator.removes[1]
	assert.Equal(t, dropFrontend.Address.AddrCluster().AsPrefixCluster(), removeDrop.prefix)
	assert.Equal(t, expectedResourceID(dropFrontend), removeDrop.resource)
	assert.Equal(t, expectedWorldLabels(ip6Addr101), removeDrop.labels)
	assert.False(t, removeDrop.flags.IsValid())
}

// TestOnFrontendChangeIgnoresNonCandidates verifies that non-candidate
// frontends are ignored entirely by onFrontendChange().
func TestOnFrontendChangeIgnoresNonCandidates(t *testing.T) {
	tests := []struct {
		name                 string
		service              *loadbalancer.Service
		svcType              loadbalancer.SVCType
		addr                 string
		scope                uint8
		defaultLBServiceIPAM string
	}{
		{
			name:                 "internal-scope",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeInternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "unspecified-ipv4",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ipAddrAny,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "unsupported-service-type",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeNodePort,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "default-nodeipam",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultNodeIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "unmanaged-loadbalancer-class",
			service:              fooSvcLBClassOther,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := loadBalancerFrontendWatcher{
				metadata:             &mockMetadataMutator{},
				defaultLBServiceIPAM: tt.defaultLBServiceIPAM,
			}
			mutator := watcher.metadata.(*mockMetadataMutator)
			frontend := newFrontend(t, tt.service, tt.svcType, tt.addr, tt.scope)

			require.NoError(t, watcher.onFrontendChange(t.Context(), statedb.Change[*loadbalancer.Frontend]{
				Object: frontend,
			}))

			assert.Empty(t, mutator.upserts)
			assert.Empty(t, mutator.removes)
		})
	}
}

// TestOnFrontendChangeUsesDefaultUnsupportedProtoAction verifies that an
// unspecified service-level action inherits the watcher's default behaviour.
func TestOnFrontendChangeUsesDefaultUnsupportedProtoAction(t *testing.T) {
	tests := []struct {
		name            string
		dropByDefault   bool
		expectUpsert    bool
		expectRemove    bool
		expectNullRoute bool
	}{
		{
			name:            "default-forward",
			dropByDefault:   false,
			expectRemove:    true,
			expectNullRoute: false,
		},
		{
			name:            "default-drop",
			dropByDefault:   true,
			expectUpsert:    true,
			expectNullRoute: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := loadBalancerFrontendWatcher{
				metadata:             &mockMetadataMutator{},
				dropByDefault:        tt.dropByDefault,
				defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
			}
			mutator := watcher.metadata.(*mockMetadataMutator)
			frontend := newFrontend(t, fooSvc, loadbalancer.SVCTypeLoadBalancer, ipAddr101, loadbalancer.ScopeExternal)

			require.NoError(t, watcher.onFrontendChange(t.Context(), statedb.Change[*loadbalancer.Frontend]{
				Object: frontend,
			}))

			if tt.expectUpsert {
				require.Len(t, mutator.upserts, 1)
				assert.Empty(t, mutator.removes)
				assert.Equal(t, expectedResourceID(frontend), mutator.upserts[0].resource)
				assert.Equal(t, expectedWorldLabels(ipAddr101), mutator.upserts[0].labels)
				assert.Equal(t, tt.expectNullRoute, mutator.upserts[0].flags.Uint8()&ipcacheTypes.FlagNullRoute != 0)
			}
			if tt.expectRemove {
				require.Len(t, mutator.removes, 1)
				assert.Empty(t, mutator.upserts)
				assert.Equal(t, expectedResourceID(frontend), mutator.removes[0].resource)
				assert.Equal(t, expectedWorldLabels(ipAddr101), mutator.removes[0].labels)
				assert.False(t, mutator.removes[0].flags.IsValid())
			}
		})
	}
}

// TestOnFrontendChangeDeletedNonCandidateIsNoOp verifies that delete events do
// not bypass candidate filtering.
func TestOnFrontendChangeDeletedNonCandidateIsNoOp(t *testing.T) {
	tests := []struct {
		name                 string
		service              *loadbalancer.Service
		svcType              loadbalancer.SVCType
		addr                 string
		scope                uint8
		defaultLBServiceIPAM string
	}{
		{
			name:                 "internal-scope",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeInternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "unspecified-ipv6",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ip6AddrAny,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "unsupported-service-type",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeHostPort,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "default-nodeipam",
			service:              fooSvc,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultNodeIPAMExtConfig.DefaultLBServiceIPAM,
		},
		{
			name:                 "unmanaged-loadbalancer-class",
			service:              fooSvcLBClassOther,
			svcType:              loadbalancer.SVCTypeLoadBalancer,
			addr:                 ipAddr101,
			scope:                loadbalancer.ScopeExternal,
			defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := loadBalancerFrontendWatcher{
				metadata:             &mockMetadataMutator{},
				defaultLBServiceIPAM: tt.defaultLBServiceIPAM,
			}
			mutator := watcher.metadata.(*mockMetadataMutator)
			frontend := newFrontend(t, tt.service, tt.svcType, tt.addr, tt.scope)

			require.NoError(t, watcher.onFrontendChange(t.Context(), statedb.Change[*loadbalancer.Frontend]{
				Deleted: true,
				Object:  frontend,
			}))

			assert.Empty(t, mutator.upserts)
			assert.Empty(t, mutator.removes)
		})
	}
}

// TestOnFrontendChangeBuildsExpectedResourceIDAndLabels verifies the metadata
// identity emitted by onFrontendChange() for both IPv4 and IPv6 frontends.
func TestOnFrontendChangeBuildsExpectedResourceIDAndLabels(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		service *loadbalancer.Service
	}{
		{
			name:    "ipv4",
			addr:    ipAddr101,
			service: barSvcWithDropAction,
		},
		{
			name:    "ipv6",
			addr:    ip6Addr101,
			service: barSvcWithDropAction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := loadBalancerFrontendWatcher{
				metadata:             &mockMetadataMutator{},
				defaultLBServiceIPAM: defaultLBIPAMExtConfig.DefaultLBServiceIPAM,
			}
			mutator := watcher.metadata.(*mockMetadataMutator)
			frontend := newFrontend(t, tt.service, loadbalancer.SVCTypeLoadBalancer, tt.addr, loadbalancer.ScopeExternal)

			require.NoError(t, watcher.onFrontendChange(t.Context(), statedb.Change[*loadbalancer.Frontend]{
				Object: frontend,
			}))

			require.Len(t, mutator.upserts, 1)
			record := mutator.upserts[0]
			assert.Equal(t, frontend.Address.AddrCluster().AsPrefixCluster(), record.prefix)
			assert.Equal(t, expectedResourceID(frontend), record.resource)
			assert.Equal(t, expectedWorldLabels(tt.addr), record.labels)
		})
	}
}

// TestOnFrontendChangePropagatesToIPCache verifies the integrated watcher path
// end-to-end. Rather than asserting internal metadata state, it registers the
// watcher with Hive and observes the resulting IPCache listener events, which
// is the public effect the rest of the system relies on.
func TestOnFrontendChangePropagatesToIPCache(t *testing.T) {
	ctx := t.Context()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	ipc := newIPCache(t, log)
	listener := newRecordingListener()
	ipc.AddListener(listener)

	lbConfig := loadbalancer.DefaultConfig
	extConfig := defaultLBIPAMExtConfig
	state := &frontendWatcherTestState{}

	h := hive.New(
		node.LocalNodeStoreTestCell,
		Cell,
		cell.Provide(
			func() loadbalancer.Config { return lbConfig },
			func() loadbalancer.ExternalConfig { return extConfig },
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
			func() *ipcache.IPCache { return ipc },
		),
		cell.Invoke(
			func(db *statedb.DB, svcTable statedb.RWTable[*loadbalancer.Service], feTable statedb.RWTable[*loadbalancer.Frontend]) {
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

	fooPrefix := cmtypes.MustParseAddrCluster(ipAddr101).AsPrefixCluster()
	barPrefix := cmtypes.MustParseAddrCluster(ip6Addr101).AsPrefixCluster()

	fooFrontendIPv4 := newFrontend(t, fooSvcWithForwardAction, loadbalancer.SVCTypeLoadBalancer, ipAddr101, loadbalancer.ScopeExternal)
	barFrontendIPv6 := newFrontend(t, barSvcWithDropAction, loadbalancer.SVCTypeLoadBalancer, ip6Addr101, loadbalancer.ScopeExternal)

	state.insertFrontend(t, fooSvcWithForwardAction, fooFrontendIPv4)
	state.insertFrontend(t, barSvcWithDropAction, barFrontendIPv6)

	upsertEvent := listener.waitFor(t, func(event listenerEvent) bool {
		return event.modType == ipcache.Upsert && event.prefix == barPrefix
	})
	assert.NotZero(t, upsertEvent.endpointFlags&ipcacheTypes.FlagNullRoute)

	_, exists := ipc.LookupByPrefix(fooPrefix.String())
	assert.False(t, exists)

	_, exists = ipc.LookupByPrefix(barPrefix.String())
	assert.True(t, exists)

	state.deleteFrontend(t, fooSvcWithForwardAction, fooFrontendIPv4)
	state.deleteFrontend(t, barSvcWithDropAction, barFrontendIPv6)

	listener.waitFor(t, func(event listenerEvent) bool {
		return event.modType == ipcache.Delete && event.prefix == barPrefix
	})

	_, exists = ipc.LookupByPrefix(fooPrefix.String())
	assert.False(t, exists)

	_, exists = ipc.LookupByPrefix(barPrefix.String())
	assert.False(t, exists)
}
