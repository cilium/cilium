// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pinning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
)

const (
	node1 = "node1"
	node2 = "node2"
	node3 = "node3"

	service1 = "service1"
	service2 = "service2"
	service3 = "service3"
)

var (
	node1Ip, _    = netip.AddrFromSlice(net.IPv4(192, 168, 0, 1).To4())
	node2Ip, _    = netip.AddrFromSlice(net.IPv4(192, 168, 0, 2).To4())
	node3Ip, _    = netip.AddrFromSlice(net.IPv4(192, 168, 0, 3).To4())
	allNodes      = []netip.Addr{node1Ip, node2Ip, node3Ip}
	pinToNode     = node2
	pinToNodeAddr = node2Ip

	Service1Ip, _ = netip.AddrFromSlice(net.IPv4(1, 2, 3, 1).To4())
	Service2Ip, _ = netip.AddrFromSlice(net.IPv4(1, 2, 3, 2).To4())
	Service3Ip, _ = netip.AddrFromSlice(net.IPv4(1, 2, 3, 3).To4())
	AllServiceIps = []netip.Addr{Service1Ip, Service2Ip, Service3Ip}

	AllServices = []ServiceInfo{
		{Name: service1, Ip: Service1Ip},
		{Name: service2, Ip: Service2Ip},
		{Name: service3, Ip: Service3Ip},
	}

	serviceAppSelector = "test"

	readyCond = readyNodeConditions()
)

type NodeInfo struct {
	Name string
	Ip   netip.Addr
}

type ServiceInfo struct {
	Name string
	Ip   netip.Addr
}

type fakeResource[T runtime.Object] chan resource.Event[T]

func (fr fakeResource[T]) sync(tb testing.TB) {
	var sync resource.Event[T]
	sync.Kind = resource.Sync
	fr.process(tb, sync)
}

func (fr fakeResource[T]) process(tb testing.TB, ev resource.Event[T]) {
	tb.Helper()
	if err := fr.processWithError(ev); err != nil {
		tb.Fatal("Failed to process event:", err)
	}
}

func (fr fakeResource[T]) processWithError(ev resource.Event[T]) error {
	errs := make(chan error)
	ev.Done = func(err error) {
		errs <- err
	}
	fr <- ev
	return <-errs
}

func (fr fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	if len(opts) > 1 {
		// Ideally we'd only ignore resource.WithRateLimit here, but that
		// isn't possible.
		panic("more than one option is not supported")
	}
	return fr
}

func (fr fakeResource[T]) Observe(ctx context.Context, next func(event resource.Event[T]), complete func(error)) {
	for {
		select {
		case event := <-fr:
			next(event)
		case <-ctx.Done():
			complete(nil)
		}
	}
}

func (fr fakeResource[T]) Store(context.Context) (resource.Store[T], error) {
	return nil, errors.New("Observe not implemented")
}

func newK8sNode(name string, internalIp netip.Addr, conditions []slim_corev1.NodeCondition) *slim_corev1.Node {
	return &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: name,
		},
		Status: slim_corev1.NodeStatus{
			Addresses: []slim_corev1.NodeAddress{
				{
					Type:    slim_corev1.NodeInternalIP,
					Address: internalIp.String(),
				},
			},
			Conditions: conditions,
		},
	}
}

func newK8sPinnedService(
	name string,
	externalIP netip.Addr,
	pinNode string,
	selector string,
) *slim_corev1.Service {
	return &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"advertise": "bgp",
			},
			Annotations: map[string]string{
				"service.cilium.io/type":             "LoadBalancer",
				"service.cilium.io/lb-algorithm":     "maglev",
				"service.cilium.io/sip-inspect":      "true",
				"service.cilium.io/svc-pinning-node": pinNode,
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Type:                  slim_corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyLocal,
			ExternalIPs:           []string{externalIP.String()},
			Selector: map[string]string{
				"app": selector,
			},
			Ports: []slim_corev1.ServicePort{
				{
					Name:       "udp",
					Protocol:   slim_corev1.ProtocolUDP,
					Port:       5061,
					TargetPort: intstr.FromInt(5061),
				},
			},
		},
	}
}

func readyNodeConditions() []slim_corev1.NodeCondition {
	return []slim_corev1.NodeCondition{
		{Type: slim_corev1.NodeReady, Status: slim_corev1.ConditionTrue},
	}
}

type PinningManagerTestSuite struct {
	manager       *PinningManager
	pinMapUpdates <-chan LbPinMapUpdateEvent
	nodes         fakeResource[*slim_corev1.Node]
	services      fakeResource[*slim_corev1.Service]
}

func NewPinningManagerTestSuite(
	t *testing.T,
	localNodeName string,
	localNodeIp netip.Addr,
	jg job.Group,
	logger *slog.Logger,
	pinMapUpdateStream *lbPinMapEventStream,
) *PinningManagerTestSuite {

	ts := &PinningManagerTestSuite{
		pinMapUpdates: stream.ToChannel(t.Context(), pinMapUpdateStream.observable),
		nodes:         make(fakeResource[*slim_corev1.Node]),
		services:      make(fakeResource[*slim_corev1.Service]),
	}

	lBMaps := lbmaps.NewFakeLBMaps()

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{
		Node: nodeTypes.Node{
			Name: localNodeName,
			IPAddresses: []nodeTypes.Address{
				{
					Type: addressing.NodeInternalIP,
					IP:   localNodeIp.AsSlice(),
				},
			},
		},
		Local: &node.LocalNodeInfo{},
	})

	mng, err := registerPinningManager(PinningParams{
		Logger:             logger,
		Nodes:              ts.nodes,
		Services:           ts.services,
		PinMapUpdateStream: pinMapUpdateStream,
		LBMaps:             lBMaps,
		JobGroup:           jg,
		LocalNodeStore:     localNodeStore,
	})
	ts.manager = mng

	require.NoError(t, err)
	require.NotNil(t, ts.manager)

	ts.manager.nodesCache[localNodeName] = localNodeIp

	return ts
}

func (ts *PinningManagerTestSuite) addNode(tb testing.TB, name string, ip netip.Addr, conditions []slim_corev1.NodeCondition) {
	ts.nodes.process(tb, resource.Event[*slim_corev1.Node]{
		Key:    resource.Key{Name: name},
		Kind:   resource.Upsert,
		Object: newK8sNode(name, ip, conditions),
	})
}

func (ts *PinningManagerTestSuite) addPinnedService(
	tb testing.TB,
	name string,
	externalIP netip.Addr,
	pinNode string,
	selector string,
) {
	ts.services.process(tb, resource.Event[*slim_corev1.Service]{
		Key:    resource.Key{Name: name},
		Kind:   resource.Upsert,
		Object: newK8sPinnedService(name, externalIP, pinNode, selector),
	})
}

func (ts *PinningManagerTestSuite) handlePinMapUpdates() {
	for event := range ts.pinMapUpdates {
		ts.manager.logger.Debug(fmt.Sprintf("pin map update: %+v", event.PinningMap))
	}
}

func waitForCachedEntities[K comparable, T any](
	t *testing.T,
	entityName string,
	entities map[K]T,
	expectedCount int,
) {
	timeout, releaseTimeout := context.WithTimeout(t.Context(), 5*time.Second)
	defer releaseTimeout()

	for {
		wait, releaseWait := context.WithTimeout(t.Context(), 100*time.Millisecond)

		select {
		case <-wait.Done():
			releaseWait()

			if len(entities) == expectedCount {
				return
			}
		case <-timeout.Done():
			t.Fatalf("too long to wait cached entities (%s)", entityName)
		}
	}
}

func (ts *PinningManagerTestSuite) Init(
	t *testing.T,
	nodes []NodeInfo,
	expectedNodeCount int,
	services []ServiceInfo,
	expectedServiceCount int,
	pinToNode string,
) {
	go ts.handlePinMapUpdates()

	ts.services.sync(t)
	ts.nodes.sync(t)

	for _, n := range nodes {
		ts.addNode(t, n.Name, n.Ip, readyCond)
	}

	for _, s := range services {
		ts.addPinnedService(t, s.Name, s.Ip, pinToNode, serviceAppSelector)
	}

	waitForCachedEntities(t, "nodes", ts.manager.nodesCache, expectedNodeCount)
	waitForCachedEntities(t, "services", ts.manager.servicesCache, expectedServiceCount)
}

func (ts *PinningManagerTestSuite) checkPinningMap(t *testing.T) {
	node, err := ts.manager.localNodeStore.Get(t.Context())
	require.NoError(t, err)

	if node.Name == pinToNode {
		pm, err := DumpPinningMap(ts.manager.lBMaps)
		require.NoError(t, err)
		require.Equal(t, 0, len(pm))

		return
	}

	pm, err := DumpPinningMap(ts.manager.lBMaps)
	require.NoError(t, err)
	require.Equal(t, 3, len(pm))

	matches := 0
	wrongPinNode := false

	for s, n := range pm {
		if slices.Contains(AllServiceIps, s.ServiceIP.Addr()) && slices.Contains(allNodes, n.NodeIP.Addr()) {
			matches++
		}
		if n.NodeIP.Addr() != pinToNodeAddr {
			wrongPinNode = true
		}
	}

	require.Equal(t, 3, matches)
	require.False(t, wrongPinNode)
}
