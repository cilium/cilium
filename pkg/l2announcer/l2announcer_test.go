// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2announcer

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type fixture struct {
	announcer          *L2Announcer
	proxyNeighborTable statedb.Table[*tables.L2AnnounceEntry]
	stateDB            *statedb.DB
	svcs               statedb.RWTable[*loadbalancer.Service]
	fes                statedb.RWTable[*loadbalancer.Frontend]
	fakePolicyStore    *fakeStore[*v2alpha1.CiliumL2AnnouncementPolicy]
}

func (f *fixture) insertService(svc *loadbalancer.Service, fes ...*loadbalancer.Frontend) {
	wtxn := f.stateDB.WriteTxn(f.svcs, f.fes)
	f.svcs.Insert(wtxn, svc)
	for _, fe := range fes {
		f.fes.Insert(wtxn, fe)
	}
	wtxn.Commit()
}

func newFixture(t testing.TB) *fixture {
	var (
		tbl    statedb.RWTable[*tables.L2AnnounceEntry]
		svcs   statedb.RWTable[*loadbalancer.Service]
		fes    statedb.RWTable[*loadbalancer.Frontend]
		db     *statedb.DB
		jg     job.Group
		logger = hivetest.Logger(t)
	)

	hive.New(
		cell.Provide(
			tables.NewL2AnnounceTable,
			loadbalancer.NewServicesTable,
			loadbalancer.NewFrontendsTable,
			func() loadbalancer.Config { return loadbalancer.DefaultConfig },
		),
		cell.Invoke(func(d *statedb.DB, t statedb.RWTable[*tables.L2AnnounceEntry], svcs_ statedb.RWTable[*loadbalancer.Service], fes_ statedb.RWTable[*loadbalancer.Frontend], jg_ job.Group) {
			db = d
			tbl = t
			jg = jg_
			svcs = svcs_
			fes = fes_
		}),
	).Populate(logger)

	fakePolicyStore := &fakeStore[*v2alpha1.CiliumL2AnnouncementPolicy]{}

	params := l2AnnouncerParams{
		Logger: logger,
		DaemonConfig: &option.DaemonConfig{
			K8sNamespace:             "kube_system",
			EnableL2Announcements:    true,
			L2AnnouncerLeaseDuration: 15 * time.Second,
			L2AnnouncerRenewDeadline: 5 * time.Second,
			L2AnnouncerRetryPeriod:   2 * time.Second,
		},
		Clientset: &k8sClient.FakeClientset{
			KubernetesFakeClientset: fake.NewSimpleClientset(),
		},
		L2AnnounceTable: tbl,
		StateDB:         db,
		JobGroup:        jg,
	}

	// Setting stores normally happens in .run which we bypass for testing purposes
	announcer := NewL2Announcer(params)
	announcer.policyStore = fakePolicyStore
	announcer.params.JobGroup = jg
	announcer.params.Services = svcs
	announcer.params.Frontends = fes
	announcer.scopedGroup = announcer.params.JobGroup.Scoped("leader-election")

	return &fixture{
		announcer:          announcer,
		proxyNeighborTable: tbl,
		stateDB:            db,
		svcs:               svcs,
		fes:                fes,
		fakePolicyStore:    fakePolicyStore,
	}
}

var _ resource.Store[runtime.Object] = (*fakeStore[runtime.Object])(nil)

type fakeStore[T runtime.Object] struct {
	slice []T
}

func (fs *fakeStore[T]) List() []T {
	return fs.slice
}

func (fs *fakeStore[T]) IterKeys() resource.KeyIter { return nil }

func (fs *fakeStore[T]) Get(obj T) (item T, exists bool, err error) {
	var def T
	return def, false, nil
}

func (fs *fakeStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	var def T
	return def, false, nil
}

func (fs *fakeStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, nil
}

func (fs *fakeStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	return nil, nil
}

func (fs *fakeStore[T]) CacheStore() cache.Store { return nil }

var _ resource.Resource[runtime.Object] = (*fakeResource[runtime.Object])(nil)

type fakeResource[T runtime.Object] struct {
	store resource.Store[T]
}

func (fr *fakeResource[T]) Observe(ctx context.Context, next func(event resource.Event[T]), complete func(error)) {
}

func (fr *fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	return make(<-chan resource.Event[T])
}

func (fr *fakeResource[T]) Store(context.Context) (resource.Store[T], error) {
	if fr.store != nil {
		return fr.store, nil
	}

	return &fakeStore[T]{}, nil
}

func blueNode() *v2.CiliumNode {
	return &v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "blue-node",
			Labels: map[string]string{
				"color": "blue",
			},
		},
	}
}

func bluePolicy() *v2alpha1.CiliumL2AnnouncementPolicy {
	return &v2alpha1.CiliumL2AnnouncementPolicy{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "blue-policy",
		},
		Spec: v2alpha1.CiliumL2AnnouncementPolicySpec{
			NodeSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"color": "blue",
				},
			},
			ServiceSelector: &slim_meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"color": "blue",
				},
			},
			ExternalIPs: true,
			Interfaces: []string{
				"eno01",
			},
		},
	}
}

func blueService() (*loadbalancer.Service, *loadbalancer.Frontend) {
	svc := &loadbalancer.Service{
		Name: loadbalancer.NewServiceName("default", "blue-service"),
		Labels: labels.Labels{
			"color": labels.NewLabel("color", "blue", "k8s"),
		},
	}
	var addr loadbalancer.L3n4Addr
	addr.ParseFromString("192.168.2.1:80/TCP")
	fe := &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			Address:     addr,
			Type:        loadbalancer.SVCTypeExternalIPs,
			ServiceName: svc.Name,
		},
		Service: svc,
	}
	return svc, fe
}

// Test the happy path, make sure that we create proxy neighbor entries
func TestHappyPath(t *testing.T) {
	fix := newFixture(t)

	fix.announcer.devices = []string{"eno01"}
	err := fix.announcer.processDevicesChanged(context.Background())
	assert.NoError(t, err)

	localNode := blueNode()
	err = fix.announcer.upsertLocalNode(context.Background(), localNode)
	assert.NoError(t, err)
	assert.Equal(t, localNode, fix.announcer.localNode)

	policy := bluePolicy()
	fix.fakePolicyStore.slice = append(fix.fakePolicyStore.slice, policy)
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)
	assert.Contains(t, fix.announcer.selectedPolicies, resource.NewKey(policy))

	svc, fe := blueService()
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	svcKey := serviceKey(svc)
	if !assert.Contains(t, fix.announcer.selectedServices, svcKey) {
		return
	}

	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[svcKey],
	})
	assert.NoError(t, err)

	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               fe.Address.Addr(),
			NetworkInterface: policy.Spec.Interfaces[0],
		},
		Origins: []resource.Key{svcKey},
	}, entries[0])
}

// Test the happy path, but in every permutation of events. It should not matter in which order objects are processed
// we should always end on the same result.
func TestHappyPathPermutations(t *testing.T) {
	addDevices := func(fix *fixture, tt *testing.T) {
		fix.announcer.devices = []string{"eno01"}
		err := fix.announcer.processDevicesChanged(context.Background())
		assert.NoError(t, err)
	}
	addPolicy := func(fix *fixture, tt *testing.T) {
		policy := bluePolicy()
		fix.fakePolicyStore.slice = append(fix.fakePolicyStore.slice, policy)
		err := fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
			Kind:   resource.Upsert,
			Key:    resource.NewKey(policy),
			Object: policy,
			Done:   func(err error) {},
		})
		assert.NoError(tt, err)
	}
	addService := func(fix *fixture, tt *testing.T) {
		svc, fe := blueService()
		fix.insertService(svc, fe)
		err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
			Deleted: false,
			Object:  svc,
		})
		assert.NoError(tt, err)
	}

	type fn struct {
		name string
		fn   func(fix *fixture, tt *testing.T)
	}
	funcs := []fn{
		{name: "policy", fn: addPolicy},
		{name: "svc", fn: addService},
		{name: "dev", fn: addDevices},
	}
	run := func(fns []fn) {
		var names []string
		for _, fn := range fns {
			names = append(names, fn.name)
		}
		t.Run(strings.Join(names, "_"), func(tt *testing.T) {
			fix := newFixture(tt)

			err := fix.announcer.upsertLocalNode(context.Background(), blueNode())
			assert.NoError(tt, err)

			for _, fn := range fns {
				fn.fn(fix, tt)
			}

			rtx := fix.stateDB.ReadTxn()
			iter := fix.proxyNeighborTable.All(rtx)
			entries := statedb.Collect(iter)
			assert.Empty(tt, entries)

			svc, fe := blueService()
			if assert.Contains(tt, fix.announcer.selectedServices, serviceKey(svc)) {
				err = fix.announcer.processLeaderEvent(leaderElectionEvent{
					typ:             leaderElectionLeading,
					selectedService: fix.announcer.selectedServices[serviceKey(svc)],
				})
				assert.NoError(tt, err)
			}

			rtx = fix.stateDB.ReadTxn()
			iter = fix.proxyNeighborTable.All(rtx)
			entries = statedb.Collect(iter)
			if assert.Len(tt, entries, 1) {
				assert.Equal(tt, &tables.L2AnnounceEntry{
					L2AnnounceKey: tables.L2AnnounceKey{
						IP:               fe.Address.Addr(),
						NetworkInterface: bluePolicy().Spec.Interfaces[0],
					},
					Origins: []resource.Key{serviceKey(svc)},
				}, entries[0])
			}
		})
	}

	// Heap's algorithm to run every permutation
	// https://en.wikipedia.org/wiki/Heap%27s_algorithm#Details_of_the_algorithm
	var generate func(k int, fns []fn)
	generate = func(k int, fns []fn) {
		if k == 1 {
			run(fns)
		} else {
			generate(k-1, fns)

			for i := range k - 1 {
				if k%2 == 0 {
					fns[i], fns[k-1] = fns[k-1], fns[i]
				} else {
					fns[0], fns[k-1] = fns[k-1], fns[0]
				}

				generate(k-1, fns)
			}
		}
	}
	generate(len(funcs), funcs)
}

// Test that when two policies select the same service, and one goes away, the service still stays selected
func TestPolicyRedundancy(t *testing.T) {
	fix := newFixture(t)

	fix.announcer.devices = []string{"eno01"}
	err := fix.announcer.processDevicesChanged(context.Background())
	assert.NoError(t, err)

	// Add local node
	localNode := blueNode()
	err = fix.announcer.upsertLocalNode(context.Background(), localNode)
	assert.NoError(t, err)
	assert.Equal(t, localNode, fix.announcer.localNode)

	// Add first policy
	policy := bluePolicy()
	fix.fakePolicyStore.slice = append(fix.fakePolicyStore.slice, policy)
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Add second policy
	policy2 := bluePolicy()
	policy2.Name = "second-blue-policy"
	fix.fakePolicyStore.slice = append(fix.fakePolicyStore.slice, policy2)
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy2),
		Object: policy2,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Add service policy
	svc, fe := blueService()
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Assert service is selected
	svcKey := serviceKey(svc)
	if !assert.Contains(t, fix.announcer.selectedServices, svcKey) {
		return
	}

	// Assert both policies selected service
	assert.Contains(t, fix.announcer.selectedServices[svcKey].byPolicies, policyKey(policy))
	assert.Contains(t, fix.announcer.selectedServices[svcKey].byPolicies, policyKey(policy2))

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[svcKey],
	})
	assert.NoError(t, err)

	// Assert selected service turned into Proxy Neighbor Entry
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               fe.Address.Addr(),
			NetworkInterface: policy.Spec.Interfaces[0],
		},
		Origins: []resource.Key{svcKey},
	}, entries[0])

	// Delete second policy
	idx := slices.Index(fix.fakePolicyStore.slice, policy2)
	fix.fakePolicyStore.slice = slices.Delete(fix.fakePolicyStore.slice, idx, idx+1)
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Delete,
		Key:    resource.NewKey(policy2),
		Object: policy2,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Assert only one policy selected
	assert.Equal(t, []resource.Key{
		policyKey(policy),
	}, fix.announcer.selectedServices[svcKey].byPolicies)

	// Assert Proxy Neighbor Entry still exists
	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               fe.Address.Addr(),
			NetworkInterface: policy.Spec.Interfaces[0],
		},
		Origins: []resource.Key{svcKey},
	}, entries[0])
}

func baseUpdateSetup(t *testing.T) *fixture {
	fix := newFixture(t)

	fix.announcer.devices = []string{"eno01"}
	err := fix.announcer.processDevicesChanged(context.Background())
	require.NoError(t, err)
	require.Len(t, fix.announcer.devices, 1)
	require.Contains(t, fix.announcer.devices, "eno01")

	localNode := blueNode()
	err = fix.announcer.upsertLocalNode(context.Background(), localNode)
	require.NoError(t, err)
	require.Equal(t, localNode, fix.announcer.localNode)

	policy := bluePolicy()
	fix.fakePolicyStore.slice = append(fix.fakePolicyStore.slice, policy)
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	require.NoError(t, err)

	require.Len(t, fix.announcer.selectedPolicies, 1)
	require.Empty(t, fix.announcer.selectedServices)

	svc, fe := blueService()
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	require.Len(t, fix.announcer.selectedPolicies, 1)
	require.Len(t, fix.announcer.selectedServices, 1)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[serviceKey(svc)],
	})
	require.NoError(t, err)

	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)

	require.Len(t, entries, 1)

	return fix
}

// Update the host labels so the currently policy does not match anymore. Assert that policies are no longer selected
// services are no longer selected and proxy neighbor entries are removed.
func TestUpdateHostLabels_NoMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	node := blueNode()
	node.Labels["color"] = "cyan"

	err := fix.announcer.processLocalNodeEvent(context.Background(), resource.Event[*v2.CiliumNode]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(node),
		Object: node,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Empty(t, fix.announcer.selectedPolicies)
	assert.Empty(t, fix.announcer.selectedServices)

	// Assert Proxy Neighbor Entry is deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)
}

// When policies and services exist that currently don't match, assert that these are added properly when the labels
// on the local node change.
func TestUpdateHostLabels_AdditionalMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	// Check that active policies and selected services is 1
	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 1)

	// Add a non matching policy
	policy := bluePolicy()
	policy.Name = "cyan-policy"
	policy.Spec.NodeSelector.MatchLabels = map[string]string{
		"hue": "cyan",
	}
	policy.Spec.ServiceSelector.MatchLabels = map[string]string{
		"hue": "cyan",
	}
	fix.fakePolicyStore.slice = append(fix.fakePolicyStore.slice, policy)
	err := fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Add a non matching service
	svc, fe := blueService()
	svc.Name = loadbalancer.NewServiceName(svc.Name.Namespace(), "cyan-service")
	svc.Labels = labels.Labels{
		"hue": labels.NewLabel("hue", "cyan", "k8s"),
	}
	fe.ServiceName = svc.Name
	require.NoError(t, fe.Address.ParseFromString("192.168.2.2:80/TCP"))
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Check that active policies and selected services is still 1
	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 1)

	// Check that proxy neighbor entries are still 1
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 1)

	node := blueNode()
	node.Labels = map[string]string{
		"color": "blue",
		"hue":   "cyan",
	}

	err = fix.announcer.processLocalNodeEvent(context.Background(), resource.Event[*v2.CiliumNode]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(node),
		Object: node,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Check that active policies and selected services are now 2
	assert.Len(t, fix.announcer.selectedPolicies, 2)
	assert.Len(t, fix.announcer.selectedServices, 2)

	// Become leader for service
	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[serviceKey(svc)],
	})
	assert.NoError(t, err)

	// Check that proxy neighbor entries are now 2
	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Len(t, entries, 2)
}

// Test that when a policy update causes a service to no longer match, that the service is removed
func TestUpdatePolicy_NoMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	policy := bluePolicy()
	policy.Spec.ServiceSelector.MatchLabels["color"] = "red"
	fix.fakePolicyStore.slice[0] = policy
	err := fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Empty(t, fix.announcer.selectedServices)

	// Assert Proxy Neighbor Entry is deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)
}

// Test that when a policy is updated to match an addition service, that it is added and reflected in the proxy
// neighbor table.
func TestUpdatePolicy_AdditionalMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	// Add a non matching service
	svc, fe := blueService()
	svc.Name = loadbalancer.NewServiceName(svc.Name.Namespace(), "cyan-service")
	fe.ServiceName = svc.Name
	svc.Labels = labels.Map2Labels(map[string]string{
		"color": "cyan",
	}, "k8s")
	require.NoError(t, fe.Address.ParseFromString("192.168.2.2:80/TCP"))
	fix.insertService(svc, fe)
	err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	policy := bluePolicy()
	policy.Spec.ServiceSelector.MatchLabels = nil
	policy.Spec.ServiceSelector.MatchExpressions = []slim_meta_v1.LabelSelectorRequirement{
		{Key: "color", Operator: slim_meta_v1.LabelSelectorOpIn, Values: []string{"blue", "cyan"}},
	}
	fix.fakePolicyStore.slice[0] = policy
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 2)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[serviceKey(svc)],
	})
	assert.NoError(t, err)

	// Assert that entries for both are added
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 2)
}

// Test service selection under various conditions
func TestPolicySelection(t *testing.T) {
	fix := baseUpdateSetup(t)

	// Setting external and LB IP to true should select a service from the baseUpdateSetup
	policy := bluePolicy()
	policy.Spec.ExternalIPs = true
	policy.Spec.LoadBalancerIPs = true
	fix.fakePolicyStore.slice[0] = policy
	err := fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 1)

	// A service with no externalIP and no LB IP should never be selected
	svc, fe := blueService()
	fe.Type = loadbalancer.SVCTypeClusterIP
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Empty(t, fix.announcer.selectedServices)

	// Setting external and LB IP to false should not select any services anymore
	policy.Spec.ExternalIPs = false
	policy.Spec.LoadBalancerIPs = false
	fix.fakePolicyStore.slice[0] = policy
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Empty(t, fix.announcer.selectedServices)

	// Updating an existing non-selected service should not select it
	svc = svc.Clone()
	fe = fe.Clone()
	fe.Type = loadbalancer.SVCTypeExternalIPs
	require.NoError(t, fe.Address.ParseFromString("192.168.2.2:80/TCP"))
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Empty(t, fix.announcer.selectedServices)

	// Adding an LB IP to an existing non-selected service should not select it
	fe = fe.Clone()
	svc = svc.Clone()
	fe.Type = loadbalancer.SVCTypeLoadBalancer
	require.NoError(t, fe.Address.ParseFromString("192.168.2.7:80/TCP"))
	fix.insertService(svc, fe)

	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Empty(t, fix.announcer.selectedServices)

	// Altering the policy to select services with LB IPs should only have an entry for LB IPs
	policy.Spec.ExternalIPs = false
	policy.Spec.LoadBalancerIPs = true
	fix.fakePolicyStore.slice[0] = policy
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)
	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 1)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[serviceKey(svc)],
	})
	assert.NoError(t, err)

	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               netip.MustParseAddr("192.168.2.7"),
			NetworkInterface: bluePolicy().Spec.Interfaces[0],
		},
		Origins: []resource.Key{serviceKey(svc)},
	})
}

// Test that when the selected IP types in the policy changes, that proxy neighbor table is updated properly.
func TestUpdatePolicy_ChangeIPType(t *testing.T) {
	fix := baseUpdateSetup(t)

	// Service has no LB IP so it should not be selected
	policy := bluePolicy()
	policy.Spec.ExternalIPs = false
	policy.Spec.LoadBalancerIPs = true
	fix.fakePolicyStore.slice[0] = policy
	err := fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Empty(t, fix.announcer.selectedServices)

	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)

	// Adding an LB IP should select the service and create an entry
	svc, fe := blueService()
	fe.Type = loadbalancer.SVCTypeLoadBalancer
	assert.NoError(t, fe.Address.ParseFromString("192.168.2.3:80/TCP"))
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 1)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[serviceKey(svc)],
	})
	assert.NoError(t, err)

	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               netip.MustParseAddr("192.168.2.3"),
			NetworkInterface: bluePolicy().Spec.Interfaces[0],
		},
		Origins: []resource.Key{serviceKey(svc)},
	})

	// changing the frontend type should unselect the service
	svc = svc.Clone()
	fe = fe.Clone()
	fe.Type = loadbalancer.SVCTypeClusterIP
	fix.insertService(svc, fe)
	err = fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Empty(t, fix.announcer.selectedServices)

	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Empty(t, entries)
}

// Test that when the interfaces in a policy change, that the proxy neighbor entries are updated.
func TestUpdatePolicy_ChangeInterfaces(t *testing.T) {
	fix := baseUpdateSetup(t)

	fix.announcer.devices = []string{"eno01", "eth0"}
	err := fix.announcer.processDevicesChanged(context.Background())
	assert.NoError(t, err)

	policy := bluePolicy()
	policy.Spec.Interfaces = []string{"eth0"}
	fix.fakePolicyStore.slice[0] = policy
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 1)

	svc, fe := blueService()

	// Check that the old entry is deleted and the new entry added
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               fe.Address.Addr(),
			NetworkInterface: "eth0",
		},
		Origins: []resource.Key{serviceKey(svc)},
	})
}

// Test that when a service deletes an IP the proxy neighbor table is updated accordingly
func TestUpdateService_DelIP(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc, fe := blueService()
	wtxn := fix.stateDB.WriteTxn(fix.fes)
	fix.fes.Delete(wtxn, fe)
	wtxn.Commit()

	err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Check that the entry for the IP was deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)
}

// Test that when a service adds and IP, the proxy neighbor table is updated accordingly.
func TestUpdateService_AddIP(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc, fe1 := blueService()
	svc = svc.Clone()
	fe1 = fe1.Clone()
	assert.NoError(t, fe1.Address.ParseFromString("192.168.2.1:80/TCP"))
	fe2 := fe1.Clone()
	assert.NoError(t, fe2.Address.ParseFromString("192.168.2.2:80/TCP"))
	fix.insertService(svc, fe1, fe2)

	err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Check that the interface on the proxy neighbor entry changed
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 2)
}

// Test that a service is removed if it no longer matches any policies
func TestUpdateService_NoMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc, fe := blueService()
	svc.Labels["color"] = labels.NewLabel("color", "red", "k8s")
	fix.insertService(svc, fe)

	err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)
}

// Test that when a service load balancer class is set to a supported value,
// it matches policies.
func TestUpdateService_LoadBalancerClassMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc, fe := blueService()
	svc.LoadBalancerClass = ptr.To[string](v2alpha1.L2AnnounceLoadBalancerClass)
	fix.insertService(svc, fe)

	err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 1)
}

// Test that when a service load balancer class is set to an unsupported value,
// it no longer matches any policies.
func TestUpdateService_LoadBalancerClassNotMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc, fe := blueService()
	svc.LoadBalancerClass = ptr.To[string]("unsupported.io/lb-class")
	fix.insertService(svc, fe)

	err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: false,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)
}

// Test that deleting a service removes its entries
func TestDelService(t *testing.T) {
	fix := baseUpdateSetup(t)

	wtxn := fix.stateDB.WriteTxn(fix.svcs, fix.fes)
	fix.svcs.DeleteAll(wtxn)
	fix.fes.DeleteAll(wtxn)
	wtxn.Commit()
	svc, _ := blueService()

	err := fix.announcer.processSvcEvent(statedb.Change[*loadbalancer.Service]{
		Deleted: true,
		Object:  svc,
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Empty(t, entries)
}

// This tests affirms that the L2 announcer behaves as expected during it lifecycle, shutting down cleanly
func TestL2AnnouncerLifecycle(t *testing.T) {
	defer testutils.GoleakVerifyNone(t, testutils.GoleakIgnoreCurrent())

	startCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	h := hive.New(
		Cell,
		cell.Provide(
			func() loadbalancer.Config { return loadbalancer.DefaultConfig },
			loadbalancer.NewFrontendsTable, statedb.RWTable[*loadbalancer.Frontend].ToTable,
			loadbalancer.NewServicesTable, statedb.RWTable[*loadbalancer.Service].ToTable,
		),
		cell.Provide(tables.NewL2AnnounceTable),
		cell.Provide(tables.NewDeviceTable, statedb.RWTable[*tables.Device].ToTable),
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableL2Announcements: true,
			}
		}),
		cell.Config(envoyCfg.SecretSyncConfig{}),
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Invoke(func(_ *L2Announcer) {}),
	)
	tlog := hivetest.Logger(t)
	err := h.Start(tlog, startCtx)
	if assert.NoError(t, err) {
		// Give everything some time to start
		time.Sleep(3 * time.Second)

		stopCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		err = h.Stop(tlog, stopCtx)
		assert.NoError(t, err)
	}
}
