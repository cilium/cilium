// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// defaultTestIfIndex is the interface index fakeLinks reports for any interface
// a test has not given an explicit index.
const defaultTestIfIndex = 1

// fakeLinks stands in for the kernel's view of interface indexes, so a test can
// simulate a netdev being re-created (new index) or disappearing.
type fakeLinks struct {
	// index overrides an interface's index; unlisted interfaces report
	// defaultTestIfIndex.
	index map[string]int
	// missing names interfaces whose lookup fails.
	missing map[string]struct{}
}

func newFakeLinks() *fakeLinks {
	return &fakeLinks{
		index:   make(map[string]int),
		missing: make(map[string]struct{}),
	}
}

func (f *fakeLinks) indexOf(ifname string) (int, error) {
	if _, gone := f.missing[ifname]; gone {
		return 0, fmt.Errorf("stub: no such interface %q", ifname)
	}
	if idx, ok := f.index[ifname]; ok {
		return idx, nil
	}
	return defaultTestIfIndex, nil
}

// fakeSenderFactory produces raSenders that do not open a raw ICMPv6 socket, so
// the reconciler's start/stop bookkeeping can be exercised in a unit test. A
// returned sender's stop() still works: cancelling its context closes done.
type fakeSenderFactory struct {
	// links supplies the index a newly constructed sender binds to, mirroring
	// a real socket binding to whatever netdev exists at open time.
	links *fakeLinks
	// failOn names interfaces whose sender construction should fail.
	failOn map[string]struct{}
	// created counts how many times each interface's sender was constructed.
	created map[string]int
}

func newFakeSenderFactory(failOn ...string) *fakeSenderFactory {
	f := &fakeSenderFactory{
		links:   newFakeLinks(),
		failOn:  make(map[string]struct{}),
		created: make(map[string]int),
	}
	for _, ifname := range failOn {
		f.failOn[ifname] = struct{}{}
	}
	return f
}

func (f *fakeSenderFactory) make(parent context.Context, _ *slog.Logger, ifname string) (*raSender, error) {
	if _, fail := f.failOn[ifname]; fail {
		return nil, fmt.Errorf("stub failure on %q", ifname)
	}
	index, err := f.links.indexOf(ifname)
	if err != nil {
		return nil, err
	}
	f.created[ifname]++
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(done)
	}()
	s := &raSender{cancel: cancel, done: done}
	s.index.Store(int32(index))
	return s, nil
}

func newTestRAReconciler(t *testing.T, factory *fakeSenderFactory) *UnnumberedRAReconciler {
	return &UnnumberedRAReconciler{
		logger:     hivetest.Logger(t),
		byInstance: make(map[string]map[string]struct{}),
		senders:    make(map[string]*raSender),
		baseCtx:    context.Background(),
		newSender:  factory.make,
		ifIndexOf:  factory.links.indexOf,
	}
}

// raParams builds ReconcileParams for an instance whose peers request the given
// unnumbered interfaces (one unnumbered peer per interface).
func raParams(instanceName string, ifaces ...string) ReconcileParams {
	var peers []v2.CiliumBGPNodePeer
	for i, ifname := range ifaces {
		peers = append(peers, v2.CiliumBGPNodePeer{
			Name: fmt.Sprintf("peer-%d", i),
			AutoDiscovery: &v2.BGPAutoDiscovery{
				Mode:       v2.BGPUnnumberedMode,
				Unnumbered: &v2.BGPUnnumbered{Interface: ifname},
			},
		})
	}
	return ReconcileParams{
		DesiredConfig: &v2.CiliumBGPNodeInstance{Name: instanceName, Peers: peers},
		CiliumNode:    &v2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "bgp-node"}},
	}
}

// runningIfaces returns the sorted set of interfaces with a live sender.
func runningIfaces(r *UnnumberedRAReconciler) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.senders))
	for ifname := range r.senders {
		out = append(out, ifname)
	}
	sort.Strings(out)
	return out
}

func TestUnnumberedRAReconciler_Basic(t *testing.T) {
	r := newTestRAReconciler(t, newFakeSenderFactory())

	require.Equal(t, UnnumberedRAReconcilerName, r.Name())
	require.Equal(t, UnnumberedRAReconcilerPriority, r.Priority())
	require.NoError(t, r.Init(&instance.BGPInstance{Name: "i"}))
	// Cleanup with a nil instance must not panic.
	require.NotPanics(t, func() { r.Cleanup(nil) })
}

func TestUnnumberedRAReconciler_SelectsOnlyUnnumberedInterfaces(t *testing.T) {
	r := newTestRAReconciler(t, newFakeSenderFactory())

	params := ReconcileParams{
		DesiredConfig: &v2.CiliumBGPNodeInstance{
			Name: "instance-1",
			Peers: []v2.CiliumBGPNodePeer{
				// Unnumbered with a real interface -> selected.
				{
					Name: "unnum",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode:       v2.BGPUnnumberedMode,
						Unnumbered: &v2.BGPUnnumbered{Interface: "net0"},
					},
				},
				// Not unnumbered -> ignored.
				{
					Name: "gw",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode:           v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{AddressFamily: "ipv4"},
					},
				},
				// No AutoDiscovery at all -> ignored.
				{Name: "static"},
				// Unnumbered mode but no unnumbered config -> ignored.
				{
					Name:          "unnum-nil",
					AutoDiscovery: &v2.BGPAutoDiscovery{Mode: v2.BGPUnnumberedMode},
				},
				// Unnumbered mode but empty interface -> ignored.
				{
					Name: "unnum-empty",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode:       v2.BGPUnnumberedMode,
						Unnumbered: &v2.BGPUnnumbered{Interface: ""},
					},
				},
			},
		},
		CiliumNode: &v2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "bgp-node"}},
	}

	require.NoError(t, r.Reconcile(context.Background(), params))
	require.Equal(t, []string{"net0"}, runningIfaces(r))
}

func TestUnnumberedRAReconciler_StartsUpdatesAndStops(t *testing.T) {
	factory := newFakeSenderFactory()
	r := newTestRAReconciler(t, factory)

	// Start two interfaces.
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0", "net1")))
	require.Equal(t, []string{"net0", "net1"}, runningIfaces(r))

	// Re-reconciling the same config is idempotent: senders are not recreated.
	sender0 := r.senders["net0"]
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0", "net1")))
	require.Same(t, sender0, r.senders["net0"], "existing sender should be reused")
	require.Equal(t, 1, factory.created["net0"])

	// Dropping net0 stops it while net1 keeps running.
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net1")))
	require.Equal(t, []string{"net1"}, runningIfaces(r))

	// Emptying the instance stops everything.
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1")))
	require.Empty(t, runningIfaces(r))
}

func TestUnnumberedRAReconciler_UnionAcrossInstances(t *testing.T) {
	r := newTestRAReconciler(t, newFakeSenderFactory())

	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0")))
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-2", "net0", "net1")))
	// Union of both instances; net0 requested by both is a single sender.
	require.Equal(t, []string{"net0", "net1"}, runningIfaces(r))

	// Removing instance-2 drops net1 but keeps net0 (still wanted by instance-1).
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-2")))
	require.Equal(t, []string{"net0"}, runningIfaces(r))

	// Cleanup of instance-1 stops the last sender.
	r.Cleanup(&instance.BGPInstance{Name: "instance-1"})
	require.Empty(t, runningIfaces(r))
}

func TestUnnumberedRAReconciler_RestartsSenderWhenInterfaceIsRecreated(t *testing.T) {
	factory := newFakeSenderFactory()
	r := newTestRAReconciler(t, factory)

	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0")))
	original := r.senders["net0"]
	require.Equal(t, defaultTestIfIndex, original.boundIndex())
	require.Equal(t, 1, factory.created["net0"])

	// The netdev is destroyed and re-created with a new index (e.g. a link
	// re-probe after the peer reboots). The sender's socket is still bound to
	// the old index, so it must be rebound.
	factory.links.index["net0"] = 42
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0")))

	require.Equal(t, []string{"net0"}, runningIfaces(r))
	require.NotSame(t, original, r.senders["net0"], "sender should have been recreated")
	require.Equal(t, 42, r.senders["net0"].boundIndex())
	require.Equal(t, 2, factory.created["net0"])

	// The superseded sender is stopped, not leaked.
	<-original.done
}

func TestUnnumberedRAReconciler_KeepsSenderWhenIndexLookupFails(t *testing.T) {
	factory := newFakeSenderFactory()
	r := newTestRAReconciler(t, factory)

	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0")))
	original := r.senders["net0"]

	// A transient lookup failure must not tear down a working sender - the
	// sender's own reopen loop owns recovery in that case.
	factory.links.missing["net0"] = struct{}{}
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0")))

	require.Same(t, original, r.senders["net0"])
	require.Equal(t, 1, factory.created["net0"])
}

func TestUnnumberedRAReconciler_KeepsSenderWhileBetweenSockets(t *testing.T) {
	factory := newFakeSenderFactory()
	r := newTestRAReconciler(t, factory)

	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0")))
	original := r.senders["net0"]

	// A bound index of 0 means the sender is mid-reopen. Even though the
	// interface index now differs, the reconciler must not race its reopen.
	original.index.Store(0)
	factory.links.index["net0"] = 42
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0")))

	require.Same(t, original, r.senders["net0"])
	require.Equal(t, 1, factory.created["net0"])
}

func TestUnnumberedRAReconciler_StartFailureIsSkippedAndRetried(t *testing.T) {
	factory := newFakeSenderFactory("net1")
	r := newTestRAReconciler(t, factory)

	// net1's sender construction fails; net0 still starts and no error is
	// surfaced from Reconcile.
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0", "net1")))
	require.Equal(t, []string{"net0"}, runningIfaces(r))

	// net1 is not memoized as running, so a subsequent reconcile retries it.
	require.NoError(t, r.Reconcile(context.Background(), raParams("instance-1", "net0", "net1")))
	require.Equal(t, []string{"net0"}, runningIfaces(r))
	require.GreaterOrEqual(t, factory.created["net0"], 1)
}
