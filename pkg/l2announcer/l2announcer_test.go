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
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

type fixture struct {
	announcer          *L2Announcer
	proxyNeighborTable statedb.Table[*tables.L2AnnounceEntry]
	stateDB            *statedb.DB
	fakeSvcStore       *fakeStore[*slim_corev1.Service]
	fakePolicyStore    *fakeStore[*v2alpha1.CiliumL2AnnouncementPolicy]
}

func newFixture(t testing.TB) *fixture {
	var (
		tbl statedb.RWTable[*tables.L2AnnounceEntry]
		db  *statedb.DB
		jr  job.Registry
		jg  job.Group
		h   cell.Health
	)

	hive.New(
		cell.Provide(tables.NewL2AnnounceTable),
		cell.Module("test", "test", cell.Invoke(func(d *statedb.DB, t statedb.RWTable[*tables.L2AnnounceEntry], h_ cell.Health, j job.Registry, jg_ job.Group) {
			d.RegisterTable(t)
			db = d
			tbl = t
			jr = j
			jg = jg_
			h = h_
		})),
	).Populate(hivetest.Logger(t))

	fakeSvcStore := &fakeStore[*slim_corev1.Service]{}
	fakePolicyStore := &fakeStore[*v2alpha1.CiliumL2AnnouncementPolicy]{}

	params := l2AnnouncerParams{
		Logger:    logrus.New(),
		Lifecycle: &cell.DefaultLifecycle{},
		Health:    h,
		DaemonConfig: &option.DaemonConfig{
			K8sNamespace:             "kube_system",
			EnableL2Announcements:    true,
			L2AnnouncerLeaseDuration: 15 * time.Second,
			L2AnnouncerRenewDeadline: 5 * time.Second,
			L2AnnouncerRetryPeriod:   2 * time.Second,
		},
		Clientset: &client.FakeClientset{
			KubernetesFakeClientset: fake.NewSimpleClientset(),
		},
		L2AnnounceTable: tbl,
		StateDB:         db,
		JobGroup:        jg,
	}

	// Setting stores normally happens in .run which we bypass for testing purposes
	announcer := NewL2Announcer(params)
	announcer.policyStore = fakePolicyStore
	announcer.svcStore = fakeSvcStore
	announcer.params.JobGroup = jr.NewGroup(h)
	announcer.scopedGroup = announcer.params.JobGroup.Scoped("leader-election")
	announcer.params.JobGroup.Start(context.Background())

	return &fixture{
		announcer:          announcer,
		proxyNeighborTable: tbl,
		stateDB:            db,
		fakeSvcStore:       fakeSvcStore,
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
func (fs *fakeStore[T]) Release()                {}

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

func blueService() *slim_corev1.Service {
	return &slim_corev1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace: "default",
			Name:      "blue-service",
			Labels: map[string]string{
				"color": "blue",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ExternalIPs: []string{"192.168.2.1"},
		},
	}
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

	svc := blueService()
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	svcKey := serviceKey(blueService())
	if !assert.Contains(t, fix.announcer.selectedServices, svcKey) {
		return
	}

	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[svcKey],
	})
	assert.NoError(t, err)

	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, entries[0], &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               netip.MustParseAddr(svc.Spec.ExternalIPs[0]),
			NetworkInterface: policy.Spec.Interfaces[0],
		},
		Origins: []resource.Key{svcKey},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
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
		svc := blueService()
		fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
		err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
			Kind:   resource.Upsert,
			Key:    resource.NewKey(svc),
			Object: svc,
			Done:   func(err error) {},
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
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				fix.announcer.params.JobGroup.Stop(ctx)
				cancel()
			}()

			err := fix.announcer.upsertLocalNode(context.Background(), blueNode())
			assert.NoError(tt, err)

			for _, fn := range fns {
				fn.fn(fix, tt)
			}

			rtx := fix.stateDB.ReadTxn()
			iter := fix.proxyNeighborTable.All(rtx)
			entries := statedb.Collect(iter)
			assert.Len(tt, entries, 0)

			if assert.Contains(tt, fix.announcer.selectedServices, serviceKey(blueService())) {
				err = fix.announcer.processLeaderEvent(leaderElectionEvent{
					typ:             leaderElectionLeading,
					selectedService: fix.announcer.selectedServices[serviceKey(blueService())],
				})
				assert.NoError(tt, err)
			}

			rtx = fix.stateDB.ReadTxn()
			iter = fix.proxyNeighborTable.All(rtx)
			entries = statedb.Collect(iter)
			if assert.Len(tt, entries, 1) {
				assert.Equal(tt, entries[0], &tables.L2AnnounceEntry{
					L2AnnounceKey: tables.L2AnnounceKey{
						IP:               netip.MustParseAddr(blueService().Spec.ExternalIPs[0]),
						NetworkInterface: bluePolicy().Spec.Interfaces[0],
					},
					Origins: []resource.Key{serviceKey(blueService())},
				})
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

			for i := 0; i < k-1; i++ {
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
	svc := blueService()
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Assert service is selected
	svcKey := serviceKey(blueService())
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
	assert.Equal(t, entries[0], &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               netip.MustParseAddr(svc.Spec.ExternalIPs[0]),
			NetworkInterface: policy.Spec.Interfaces[0],
		},
		Origins: []resource.Key{svcKey},
	})

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
	assert.Equal(t, entries[0], &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               netip.MustParseAddr(svc.Spec.ExternalIPs[0]),
			NetworkInterface: policy.Spec.Interfaces[0],
		},
		Origins: []resource.Key{svcKey},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
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
	require.Len(t, fix.announcer.selectedServices, 0)

	svc := blueService()
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	require.NoError(t, err)

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

	assert.Len(t, fix.announcer.selectedPolicies, 0)
	assert.Len(t, fix.announcer.selectedServices, 0)

	// Assert Proxy Neighbor Entry is deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
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
	svc := blueService()
	svc.Name = "cyan-service"
	svc.Labels = map[string]string{
		"hue": "cyan",
	}
	svc.Spec.ExternalIPs = []string{"192.168.2.2"}
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
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
	assert.Len(t, fix.announcer.selectedServices, 0)

	// Assert Proxy Neighbor Entry is deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// Test that when a policy is updated to match an addition service, that it is added and reflected in the proxy
// neighbor table.
func TestUpdatePolicy_AdditionalMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	// Add a non matching service
	svc := blueService()
	svc.Name = "cyan-service"
	svc.Labels = map[string]string{
		"color": "cyan",
	}
	svc.Spec.ExternalIPs = []string{"192.168.2.2"}
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
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
	svc := blueService()
	svc.Spec.ExternalIPs = nil
	svc.Status.LoadBalancer.Ingress = nil
	fix.fakeSvcStore.slice[0] = svc
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 0)

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
	assert.Len(t, fix.announcer.selectedServices, 0)

	// Updating an existing non-selected service should not select it
	svc.Spec = slim_corev1.ServiceSpec{
		ExternalIPs: []string{"192.168.2.2"},
	}
	fix.fakeSvcStore.slice[0] = svc
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 0)

	// Adding an LB IP to an existing non-selected service should not select it
	svc.Status.LoadBalancer.Ingress = []slim_corev1.LoadBalancerIngress{
		{IP: "192.168.2.7"},
	}
	fix.fakeSvcStore.slice[0] = svc
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 0)

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
		Origins: []resource.Key{resource.NewKey(svc)},
	})

	// A service with an LB hostname but not an LB IP should not be selected
	svc.Status.LoadBalancer.Ingress = []slim_corev1.LoadBalancerIngress{
		{Hostname: "example.com"},
	}
	fix.fakeSvcStore.slice[0] = svc
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 0)

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
	assert.Len(t, fix.announcer.selectedServices, 0)

	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	// Adding an LB IP should select the service and create an entry
	svc := blueService()
	svc.Spec.ExternalIPs = nil
	svc.Status.LoadBalancer.Ingress = []slim_corev1.LoadBalancerIngress{
		{IP: "192.168.2.3"},
	}
	fix.fakeSvcStore.slice[0] = svc
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
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

	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               netip.MustParseAddr("192.168.2.3"),
			NetworkInterface: bluePolicy().Spec.Interfaces[0],
		},
		Origins: []resource.Key{resource.NewKey(svc)},
	})

	// Setting an empty LB IP should unselect the service
	svc.Status.LoadBalancer.Ingress = []slim_corev1.LoadBalancerIngress{
		{IP: ""},
	}
	fix.fakeSvcStore.slice[0] = svc
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	assert.Len(t, fix.announcer.selectedPolicies, 1)
	assert.Len(t, fix.announcer.selectedServices, 0)

	rtx = fix.stateDB.ReadTxn()
	iter = fix.proxyNeighborTable.All(rtx)
	entries = statedb.Collect(iter)
	assert.Len(t, entries, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
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

	// Check that the old entry is deleted and the new entry added
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		L2AnnounceKey: tables.L2AnnounceKey{
			IP:               netip.MustParseAddr(blueService().Spec.ExternalIPs[0]),
			NetworkInterface: "eth0",
		},
		Origins: []resource.Key{resource.NewKey(blueService())},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// Test that when a service deletes an IP the proxy neighbor table is updated accordingly
func TestUpdateService_DelIP(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc := blueService()
	svc.Spec.ExternalIPs = []string{}
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Check that the entry for the IP was deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// Test that when a service adds and IP, the proxy neighbor table is updated accordingly.
func TestUpdateService_AddIP(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc := blueService()
	svc.Spec.ExternalIPs = []string{"192.168.2.1", "192.168.2.2"}
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Check that the interface on the proxy neighbor entry changed
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// Test that a service is removed if it no longer matches any policies
func TestUpdateService_NoMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc := blueService()
	svc.Labels["color"] = "red"
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// Test that when a service load balancer class is set to a supported value,
// it matches policies.
func TestUpdateService_LoadBalancerClassMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc := blueService()
	svc.Spec.LoadBalancerClass = ptr.To[string](v2alpha1.L2AnnounceLoadBalancerClass)
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// Test that when a service load balancer class is set to an unsupported value,
// it no longer matches any policies.
func TestUpdateService_LoadBalancerClassNotMatch(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc := blueService()
	svc.Spec.LoadBalancerClass = ptr.To[string]("unsupported.io/lb-class")
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// Test that deleting a service removes its entries
func TestDelService(t *testing.T) {
	fix := baseUpdateSetup(t)

	svc := blueService()
	fix.fakeSvcStore.slice = nil
	err := fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Delete,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Check that the entry got deleted
	rtx := fix.stateDB.ReadTxn()
	iter := fix.proxyNeighborTable.All(rtx)
	entries := statedb.Collect(iter)
	assert.Len(t, entries, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.params.JobGroup.Stop(ctx)
	cancel()
}

// This tests affirms that the L2 announcer behaves as expected during it lifecycle, shutting down cleanly
func TestL2AnnouncerLifecycle(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	startCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	h := hive.New(
		Cell,
		cell.Provide(tables.NewL2AnnounceTable),
		cell.Invoke(statedb.RegisterTable[*tables.L2AnnounceEntry]),
		cell.Provide(tables.NewDeviceTable, statedb.RWTable[*tables.Device].ToTable),
		cell.Invoke(statedb.RegisterTable[*tables.Device]),
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableL2Announcements: true,
			}
		}),
		client.FakeClientCell,
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
