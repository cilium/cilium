// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2announcer

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

type fixture struct {
	announcer          *L2Announcer
	proxyNeighborTable statedb.Table[*tables.L2AnnounceEntry]
	stateDB            statedb.DB
	fakeSvcStore       *fakeStore[*slim_corev1.Service]
	fakePolicyStore    *fakeStore[*v2alpha1.CiliumL2AnnouncementPolicy]
}

func newFixture() *fixture {
	var (
		tbl statedb.Table[*tables.L2AnnounceEntry]
		db  statedb.DB
		jr  job.Registry
	)

	hive.New(
		statedb.Cell,
		tables.Cell,
		job.Cell,
		cell.Invoke(func(d statedb.DB, t statedb.Table[*tables.L2AnnounceEntry], j job.Registry) {
			db = d
			tbl = t
			jr = j
		}),
	).Populate()

	fakeSvcStore := &fakeStore[*slim_corev1.Service]{}
	fakePolicyStore := &fakeStore[*v2alpha1.CiliumL2AnnouncementPolicy]{}

	params := l2AnnouncerParams{
		Logger:    logrus.New(),
		Lifecycle: &hive.DefaultLifecycle{},
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
		JobRegistry:     jr,
	}

	// Setting stores normally happens in .run which we bypass for testing purposes
	announcer := NewL2Announcer(params)
	announcer.policyStore = fakePolicyStore
	announcer.svcStore = fakeSvcStore
	announcer.jobgroup = jr.NewGroup()
	announcer.jobgroup.Start(context.Background())

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
func (fs *fakeStore[T]) CacheStore() cache.Store { return nil }

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
	fix := newFixture()

	err := fix.announcer.processDevicesChanged(context.Background(), []string{"eno01"})
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

	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 0)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[svcKey],
	})
	assert.NoError(t, err)

	r = fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err = r.Get(statedb.All)
	assert.NoError(t, err)
	entries = statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, entries[0], &tables.L2AnnounceEntry{
		IP:               net.ParseIP(svc.Spec.ExternalIPs[0]),
		NetworkInterface: policy.Spec.Interfaces[0],
		Origins:          []resource.Key{svcKey},
		Deleted:          false,
		Revision:         1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
	cancel()
}

// Test the happy path, but in every permutation of events. It should not matter in which order objects are processed
// we should always end on the same result.
func TestHappyPathPermutations(t *testing.T) {
	addDevices := func(fix *fixture, tt *testing.T) {
		err := fix.announcer.processDevicesChanged(context.Background(), []string{"eno01"})
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
			fix := newFixture()
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				fix.announcer.jobgroup.Stop(ctx)
				cancel()
			}()

			err := fix.announcer.upsertLocalNode(context.Background(), blueNode())
			assert.NoError(tt, err)

			for _, fn := range fns {
				fn.fn(fix, tt)
			}

			r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
			iter, err := r.Get(statedb.All)
			assert.NoError(tt, err)
			entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
			assert.Len(tt, entries, 0)

			if assert.Contains(tt, fix.announcer.selectedServices, serviceKey(blueService())) {
				err = fix.announcer.processLeaderEvent(leaderElectionEvent{
					typ:             leaderElectionLeading,
					selectedService: fix.announcer.selectedServices[serviceKey(blueService())],
				})
				assert.NoError(tt, err)
			}

			r = fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
			iter, err = r.Get(statedb.All)
			assert.NoError(tt, err)
			entries = statedb.Collect[*tables.L2AnnounceEntry](iter)
			if assert.Len(tt, entries, 1) {
				// We don't care about the amount of revisions.
				entries[0].Revision = 1
				assert.Equal(tt, entries[0], &tables.L2AnnounceEntry{
					IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
					NetworkInterface: bluePolicy().Spec.Interfaces[0],
					Origins:          []resource.Key{serviceKey(blueService())},
					Deleted:          false,
					Revision:         1,
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

// Test that when two policies select the same service, an one goes away, the service still stays selected
func TestPolicyRedundancy(t *testing.T) {
	fix := newFixture()

	err := fix.announcer.processDevicesChanged(context.Background(), []string{"eno01"})
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
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, entries[0], &tables.L2AnnounceEntry{
		IP:               net.ParseIP(svc.Spec.ExternalIPs[0]),
		NetworkInterface: policy.Spec.Interfaces[0],
		Origins:          []resource.Key{svcKey},
		Deleted:          false,
		Revision:         1,
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
	r = fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err = r.Get(statedb.All)
	assert.NoError(t, err)
	entries = statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, entries[0], &tables.L2AnnounceEntry{
		IP:               net.ParseIP(svc.Spec.ExternalIPs[0]),
		NetworkInterface: policy.Spec.Interfaces[0],
		Origins:          []resource.Key{svcKey},
		Deleted:          false,
		Revision:         1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
	cancel()
}

// Test that when the last policy selecting a service is deleted, the selected service and proxy neighbor entries go
// away.
func TestPolicySoftDeleteService(t *testing.T) {
	fix := newFixture()

	err := fix.announcer.processDevicesChanged(context.Background(), []string{"eno01"})
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
	assert.Equal(t, []resource.Key{
		policyKey(policy),
	}, fix.announcer.selectedServices[svcKey].byPolicies)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[svcKey],
	})
	assert.NoError(t, err)

	// Assert selected service turned into Proxy Neighbor Entry
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, entries[0], &tables.L2AnnounceEntry{
		IP:               net.ParseIP(svc.Spec.ExternalIPs[0]),
		NetworkInterface: policy.Spec.Interfaces[0],
		Origins:          []resource.Key{svcKey},
		Deleted:          false,
		Revision:         1,
	})

	// Delete policy
	idx := slices.Index(fix.fakePolicyStore.slice, policy)
	fix.fakePolicyStore.slice = slices.Delete(fix.fakePolicyStore.slice, idx, idx+1)
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Delete,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	// Assert no services selected anymore
	assert.Len(t, fix.announcer.selectedServices, 0)

	// Assert Proxy Neighbor Entry is soft deleted
	r = fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err = r.Get(statedb.All)
	assert.NoError(t, err)
	entries = statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(svc.Spec.ExternalIPs[0]),
		NetworkInterface: policy.Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         2,
	}, entries[0])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
	cancel()
}

func baseUpdateSetup(t *testing.T) *fixture {
	fix := newFixture()

	err := fix.announcer.processDevicesChanged(context.Background(), []string{"eno01"})
	assert.NoError(t, err)

	localNode := blueNode()
	err = fix.announcer.upsertLocalNode(context.Background(), localNode)
	assert.NoError(t, err)

	policy := bluePolicy()
	fix.fakePolicyStore.slice = append(fix.fakePolicyStore.slice, policy)
	err = fix.announcer.processPolicyEvent(context.Background(), resource.Event[*v2alpha1.CiliumL2AnnouncementPolicy]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(policy),
		Object: policy,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	svc := blueService()
	fix.fakeSvcStore.slice = append(fix.fakeSvcStore.slice, svc)
	err = fix.announcer.processSvcEvent(resource.Event[*slim_corev1.Service]{
		Kind:   resource.Upsert,
		Key:    resource.NewKey(svc),
		Object: svc,
		Done:   func(err error) {},
	})
	assert.NoError(t, err)

	err = fix.announcer.processLeaderEvent(leaderElectionEvent{
		typ:             leaderElectionLeading,
		selectedService: fix.announcer.selectedServices[serviceKey(svc)],
	})
	assert.NoError(t, err)

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

	// Assert Proxy Neighbor Entry is soft deleted
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         2,
	}, entries[0])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
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
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
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
	r = fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err = r.Get(statedb.All)
	assert.NoError(t, err)
	entries = statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
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

	// Assert Proxy Neighbor Entry is soft deleted
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Equal(t, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         2,
	}, entries[0])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
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
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
	cancel()
}

// Test that when the selected IP types in the policy changes, that proxy neighbor table is updated properly.
func TestUpdatePolicy_ChangeIPType(t *testing.T) {
	fix := baseUpdateSetup(t)

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
	assert.Len(t, fix.announcer.selectedServices, 1)

	// Selected service has no LB ips, so all entries should be soft deleted
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         2,
	})

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

	// Adding a LB IP, check that we have an entry for that
	r = fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err = r.Get(statedb.All)
	assert.NoError(t, err)
	entries = statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 2)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		IP:               net.ParseIP("192.168.2.3"),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{resource.NewKey(svc)},
		Deleted:          false,
		Revision:         3,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
	cancel()
}

// Test that when the interfaces in a policy change, that the proxy neighbor entries are updated.
func TestUpdatePolicy_ChangeInterfaces(t *testing.T) {
	fix := baseUpdateSetup(t)

	err := fix.announcer.processDevicesChanged(context.Background(), []string{"eno01", "eth0"})
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

	// Check that the old entry is soft deleted and the new entry added
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         3,
	})
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: "eth0",
		Origins:          []resource.Key{resource.NewKey(blueService())},
		Deleted:          false,
		Revision:         3,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
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
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
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
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Len(t, entries, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
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

	// Check that the entry got soft deleted
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
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

	// Check that the entry got soft deleted
	r := fix.proxyNeighborTable.Reader(fix.stateDB.ReadTxn())
	iter, err := r.Get(statedb.All)
	assert.NoError(t, err)
	entries := statedb.Collect[*tables.L2AnnounceEntry](iter)
	assert.Contains(t, entries, &tables.L2AnnounceEntry{
		IP:               net.ParseIP(blueService().Spec.ExternalIPs[0]),
		NetworkInterface: bluePolicy().Spec.Interfaces[0],
		Origins:          []resource.Key{},
		Deleted:          true,
		Revision:         2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	fix.announcer.jobgroup.Stop(ctx)
	cancel()
}
