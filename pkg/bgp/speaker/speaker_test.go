// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package speaker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metallbbgp "go.universe.tf/metallb/pkg/bgp"
	"go.universe.tf/metallb/pkg/k8s/types"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/bgp/fence"
	"github.com/cilium/cilium/pkg/bgp/mock"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	DefaultTimeout = 60 * time.Second
)

var (
	errTimeout = errors.New("timeout occurred before mock received event")
)

// TestSpeakerOnUpdateService confirms the speaker performs the correct
// actions when an OnUpdateService event takes place.
func TestSpeakerOnUpdateService(t *testing.T) {
	// gen our test structures
	service, _, metallbService, serviceID := mock.GenTestServicePairs()
	endpoints, _, metallbendpoints := mock.GenTestEndpointsPairs()

	// our test will block on this ctx, our mock will cancel it and thus
	// unblock our test. If the event never gets to our mock, a timeout
	// will occur and fail the test.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	// the mock endpointgetter will simply return a fake endpoints struct
	// returned by our gen functions when called.
	mockEndGetter := &mock.MockEndpointGetter{
		GetEndpointsOfService_: func(svcID k8s.ServiceID) *k8s.Endpoints {
			return &endpoints
		},
	}

	var rr struct {
		lock.Mutex
		name string
		svc  *metallbspr.Service
		eps  *metallbspr.Endpoints
	}

	// when our mock metallb speaker has it's SetService method called this function will delegate for it,
	// in the delegate we record the arguments with a response recorder for later retrieval and cancel the ctx
	// effectively unblocking our test function.
	mock := &mock.MockMetalLBSpeaker{
		SetService_: func(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState {
			rr.Lock()
			rr.name, rr.svc, rr.eps = name, svc, eps
			rr.Unlock()
			// will unblock our test code, defer used to be more
			// realistic as MetalLB code will return before the downstream
			// code reacts.
			defer cancel()
			return types.SyncStateSuccess
		},
	}

	spkr := &MetalLBSpeaker{
		Fencer:          fence.Fencer{},
		speaker:         mock,
		announceLBIP:    true,
		announcePodCIDR: true,
		queue:           workqueue.New(),
		services:        make(map[k8s.ServiceID]*slim_corev1.Service),
		endpointsGetter: mockEndGetter,
	}

	go spkr.run(ctx)

	err := spkr.OnUpdateService(&service)
	if err != nil {
		t.Fatal(err)
	}

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(errTimeout)
	}

	rr.Lock() // we'll do this just so race detector doen't bark at us.
	defer rr.Unlock()

	// confirm we recorded the correct metallb service name
	// this should match our generated ServiceID.
	if rr.name != serviceID.String() {
		t.Fatalf("got: %v, want: %v", rr.name, serviceID.String())
	}
	if !cmp.Equal(rr.svc, &metallbService) {
		t.Fatalf(cmp.Diff(rr.svc, metallbService))
	}
	if !cmp.Equal(rr.eps, &metallbendpoints) {
		t.Fatalf(cmp.Diff(rr.eps, metallbendpoints))
	}

	// confirm spkr appended service to map
	servicePrime, ok := spkr.services[serviceID]
	if !ok {
		t.Fatalf("speaker did not append slim_corev1.Service object to its services map.")
	}
	if !cmp.Equal(servicePrime, &service) {
		t.Fatalf(cmp.Diff(servicePrime, service))
	}
}

// TestSpeakerOnDeleteService confirms the speaker performs the correct
// actions when an OnDeleteService event takes place.
func TestSpeakerOnDeleteService(t *testing.T) {
	// gen our test structures
	service, _, _, serviceID := mock.GenTestServicePairs()

	// our test will block on this ctx, our mock will cancel it and thus
	// unblock our test. If the event never gets to our mock, a timeout
	// will occur and fail the test.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	var rr struct {
		lock.Mutex
		name string
		svc  *metallbspr.Service
		eps  *metallbspr.Endpoints
	}

	// when our mock metallb speaker has it's SetService method called this function will delegate for it,
	// in the delegate we record the arguments with a response recorder for later retrieval and cancel the ctx
	// effectively unblocking our test function.
	mock := &mock.MockMetalLBSpeaker{
		SetService_: func(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState {
			rr.Lock()
			rr.name, rr.svc, rr.eps = name, svc, eps
			rr.Unlock()
			// will unblock our test code, defer used to be more
			// realistic as MetalLB code will return before the downstream
			// code reacts.
			defer cancel()
			return types.SyncStateSuccess
		},
	}

	// in this test, we want to construct our speaker
	// with a "known" service, and test that it is deleted.
	spkr := &MetalLBSpeaker{
		Fencer:          fence.Fencer{},
		speaker:         mock,
		announceLBIP:    true,
		announcePodCIDR: true,
		queue:           workqueue.New(),
		services: map[k8s.ServiceID]*slim_corev1.Service{
			serviceID: &service,
		},
	}

	go spkr.run(ctx)

	err := spkr.OnDeleteService(&service)
	if err != nil {
		t.Fatal(err)
	}

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(errTimeout)
	}

	rr.Lock() // we'll do this just so race detector doen't bark at us.
	defer rr.Unlock()

	// confirm we recorded the correct metallb service name
	// this should match our generated ServiceID.
	if rr.name != serviceID.String() {
		t.Fatalf("got: %v, want: %v", rr.name, serviceID.String())
	}

	// confirm these are nil, they should not be set
	// on a OnDeletService call.
	if rr.svc != nil {
		t.Fatalf("got: %v, want: nil", rr.svc)
	}
	if rr.eps != nil {
		t.Fatalf("got: %v, want: nil", rr.eps)
	}

	// confirm spkr removed service to map
	_, ok := spkr.services[serviceID]
	if ok {
		t.Fatalf("speaker did not delete slim_corev1.Service object to its services map.")
	}
}

// TestSpeakerOnUpdateEndpoints confirms the speaker performs the correct
// actions when an OnUpdateEndpoints event takes place.
func TestSpeakerOnUpdateEndpoints(t *testing.T) {
	// gen our test structures
	service, _, metallbService, serviceID := mock.GenTestServicePairs()
	_, slimendpoints, metallbendpoints := mock.GenTestEndpointsPairs()

	// our test will block on this ctx, our mock will cancel it and thus
	// unblock our test. If the event never gets to our mock, a timeout
	// will occur and fail the test.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	var rr struct {
		lock.Mutex
		name string
		svc  *metallbspr.Service
		eps  *metallbspr.Endpoints
	}

	// when our mock metallb speaker has it's SetService method called this function will delegate for it,
	// in the delegate we record the arguments with a response recorder for later retrieval and cancel the ctx
	// effectively unblocking our test function.
	mock := &mock.MockMetalLBSpeaker{
		SetService_: func(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState {
			rr.Lock()
			rr.name, rr.svc, rr.eps = name, svc, eps
			rr.Unlock()
			// will unblock our test code, defer used to be more
			// realistic as MetalLB code will return before the downstream
			// code reacts.
			defer cancel()
			return types.SyncStateSuccess
		},
	}

	// in this test we expect the service associated with the endpoints
	// to exist as a lookup of the service is done in the OnUpdateEndpoints
	// call.
	spkr := &MetalLBSpeaker{
		Fencer:          fence.Fencer{},
		speaker:         mock,
		announceLBIP:    true,
		announcePodCIDR: true,
		queue:           workqueue.New(),
		services: map[k8s.ServiceID]*slim_corev1.Service{
			serviceID: &service,
		},
	}

	go spkr.run(ctx)

	err := spkr.OnUpdateEndpoints(&slimendpoints)
	if err != nil {
		t.Fatal(err)
	}

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(errTimeout)
	}

	rr.Lock() // we'll do this just so race detector doen't bark at us.
	defer rr.Unlock()

	// confirm we recorded the correct metallb service name
	// this should match our generated ServiceID.
	if rr.name != serviceID.String() {
		t.Fatalf("got: %v, want: %v", rr.name, serviceID.String())
	}

	// confirm the recorded MetalLBService and MetalLBEndpoints
	// are equal to our generated mocks.
	if !cmp.Equal(rr.svc, &metallbService) {
		t.Fatalf(cmp.Diff(rr.svc, metallbService))
	}
	if !cmp.Equal(rr.eps, &metallbendpoints) {
		t.Fatalf(cmp.Diff(rr.eps, metallbendpoints))
	}
}

// TestSpeakerOnUpdateNode confirms the speaker performs the correct
// actions when an OnUpdateNode event takes place.
//
// This test effectively covers the OnAddNode method as well,
// executing the same code path after the event is queued.
func TestSpeakerOnUpdateNode(t *testing.T) {
	// gen our test structures
	node, advs := mock.GenTestNodeAndAdvertisements()

	// our test will block on this ctx, our mock will cancel it and thus
	// unblock our test. If the event never gets to our mock, a timeout
	// will occur and fail the test.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	var rr struct {
		lock.Mutex
		labels map[string]string
		advs   []*metallbbgp.Advertisement
	}

	// launch a concurrent observer of callCount
	// when the observer sees our mocks being called
	// the necessary amount of times it'll cancel the ctx
	// and unblock our test.
	//
	// the 3 calls we expect:
	// MockSession.Set
	// MockMetalLBSpeaker.SetNodeLabels
	// MockMetalLBSpeaker.PeerSession
	var callCount int32
	go func() {
		for atomic.LoadInt32(&callCount) != 3 {
			// should be a very short spin if tests are
			// passing.
		}
		cancel()
	}()

	// when our mock session's Set method is called this function
	// will delegate for it.
	//
	// record its arguments and atomically update callCount
	mockSession := &mock.MockSession{
		Set_: func(advs ...*metallbbgp.Advertisement) error {
			rr.Lock()
			rr.advs = advs
			rr.Unlock()
			atomic.AddInt32(&callCount, 1)
			return nil
		},
	}

	// when our mock has it's SetNodeLabel and PeerSession method calls these
	// two functions wil delegate for them.
	//
	// we record the arguments and return our mock session object respectively.
	mock := &mock.MockMetalLBSpeaker{
		SetNodeLabels_: func(labels map[string]string) types.SyncState {
			rr.Lock()
			rr.labels = labels
			rr.Unlock()
			atomic.AddInt32(&callCount, 1)
			return types.SyncStateSuccess
		},
		GetBGPController_: func() *metallbspr.BGPController {
			atomic.AddInt32(&callCount, 1)
			return &metallbspr.BGPController{
				SvcAds: make(map[string][]*metallbbgp.Advertisement),
				Peers: []*metallbspr.Peer{
					{
						BGP: mockSession,
					},
				},
			}
		},
	}

	spkr := &MetalLBSpeaker{
		Fencer:          fence.Fencer{},
		speaker:         mock,
		announceLBIP:    true,
		announcePodCIDR: true,
		queue:           workqueue.New(),
	}

	go spkr.run(ctx)

	err := spkr.OnUpdateNode(&node, &node, nil)
	if err != nil {
		t.Fatal(err)
	}

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(errTimeout)
	}

	rr.Lock() // we'll do this just so race detector doen't bark at us.
	defer rr.Unlock()

	// confirm the recorded Labels and bgp advertisements
	// are equal to our generated mocks.
	if !cmp.Equal(rr.labels, node.Labels) {
		t.Fatalf(cmp.Diff(rr.labels, node.Labels))
	}
	if !cmp.Equal(rr.advs, advs) {
		t.Fatalf(cmp.Diff(rr.advs, advs))
	}
}

// TestSpeakerOnDeleteNode confirms the speaker performs the correct
// actions when an OnDeleteNode event takes place.
//
// This test also confirms that sending a DeleteNode event to the speaker
// shuts it down, issuing ErrShutDown for any subsequent event method call on
// the speaker.
func TestSpeakerOnDeleteNode(t *testing.T) {
	// gen our test structures
	node, _ := mock.GenTestNodeAndAdvertisements()
	advs := []*metallbbgp.Advertisement{} // we expect an empty list

	// our test will block on this ctx, our mock will cancel it and thus
	// unblock our test. If the event never gets to our mock, a timeout
	// will occur and fail the test.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	var rr struct {
		lock.Mutex
		advs []*metallbbgp.Advertisement
	}

	// launch a concurrent observer of callCount
	// when the observer sees our mocks being called
	// the necessary amount of times it'll cancel the ctx
	// and unblock our test.
	//
	// the 2 calls we expect:
	// MockSession.Set
	// MockMetalLBSpeaker.PeerSession
	var callCount int32
	go func() {
		for atomic.LoadInt32(&callCount) != 2 {
			// should be a very short spin if tests are
			// passing.
		}
		cancel()
	}()

	// when our mock session's Set method is called this function
	// will delegate for it.
	//
	// record its arguments and atomically update callCount
	mockSession := &mock.MockSession{
		Set_: func(advs ...*metallbbgp.Advertisement) error {
			rr.Lock()
			rr.advs = advs
			rr.Unlock()
			atomic.AddInt32(&callCount, 1)
			return nil
		},
	}

	// when our mock has its PeerSession function called it
	// will return our mock session.
	mock := &mock.MockMetalLBSpeaker{
		PeerSession_: func() []metallbspr.Session {
			atomic.AddInt32(&callCount, 1)
			return []metallbspr.Session{mockSession}
		},
		GetBGPController_: func() *metallbspr.BGPController {
			return &metallbspr.BGPController{
				SvcAds: make(map[string][]*metallbbgp.Advertisement),
				Peers: []*metallbspr.Peer{
					{
						BGP: mockSession,
					},
				},
			}
		},
	}

	spkr := &MetalLBSpeaker{
		Fencer:          fence.Fencer{},
		speaker:         mock,
		announceLBIP:    true,
		announcePodCIDR: true,
		queue:           workqueue.New(),
	}

	go spkr.run(ctx)

	err := spkr.OnDeleteNode(&node, nil)
	if err != nil {
		t.Fatal(err)
	}

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(errTimeout)
	}

	rr.Lock() // we'll do this just so race detector doen't bark at us.
	defer rr.Unlock()

	// confirm we recorded an empty slice of advertisements
	// this informs MetalLB to withdrawal all routes.
	if !cmp.Equal(rr.advs, advs) {
		t.Fatalf(cmp.Diff(rr.advs, advs))
	}

	// confirm speaker rejects any further events.
	if !spkr.shutDown() {
		t.Fatalf("wanted speaker to be shutdown")
	}
	if err := spkr.OnAddNode(nil, nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
	if err := spkr.OnDeleteNode(nil, nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
	if err := spkr.OnAddCiliumNode(nil, nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
	if err := spkr.OnDeleteCiliumNode(nil, nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
	if err := spkr.OnDeleteService(nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
	if err := spkr.OnUpdateEndpoints(nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
	if err := spkr.OnUpdateNode(nil, nil, nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
	if err := spkr.OnUpdateService(nil); !errors.Is(err, ErrShutDown) {
		t.Fatalf("got: %v, want: %v", err, ErrShutDown)
	}
}

func TestSpeakerOnUpdateAndDeleteCiliumNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	labelChan := make(chan map[string]string, 1)
	advertisementChan := make(chan []*metallbbgp.Advertisement, 1)

	mockSession := &mock.MockSession{
		Set_: func(advs ...*metallbbgp.Advertisement) error {
			advertisementChan <- advs
			return nil
		},
	}

	mockSpeaker := &mock.MockMetalLBSpeaker{
		SetNodeLabels_: func(labels map[string]string) types.SyncState {
			labelChan <- labels
			return types.SyncStateSuccess
		},
		PeerSession_: func() []metallbspr.Session {
			return []metallbspr.Session{mockSession}
		},
		GetBGPController_: func() *metallbspr.BGPController {
			return &metallbspr.BGPController{
				SvcAds: make(map[string][]*metallbbgp.Advertisement),
				Peers: []*metallbspr.Peer{
					{
						BGP: mockSession,
					},
				},
			}
		},
	}

	spkr := &MetalLBSpeaker{
		Fencer:          fence.Fencer{},
		speaker:         mockSpeaker,
		announceLBIP:    true,
		announcePodCIDR: true,
		queue:           workqueue.New(),
	}

	go spkr.run(ctx)

	// CiliumNode with one pod CIDR
	node, advs := mock.GenTestCiliumNodeAndAdvertisements(1)
	err := spkr.OnUpdateCiliumNode(nil, &node, nil)
	if err != nil {
		t.Fatal(err)
	}

	receivedLabels := <-labelChan
	if !cmp.Equal(receivedLabels, node.Labels) {
		t.Fatalf(cmp.Diff(receivedLabels, node.Labels))
	}

	receivedAdvs := <-advertisementChan
	if !cmp.Equal(receivedAdvs, advs) {
		t.Fatalf(cmp.Diff(receivedAdvs, advs))
	}

	// Add two additional pod CIDRs to CiliumNode
	oldNode := node
	node, advs = mock.GenTestCiliumNodeAndAdvertisements(3)
	err = spkr.OnUpdateCiliumNode(&oldNode, &node, nil)
	if err != nil {
		t.Fatal(err)
	}

	receivedLabels = <-labelChan
	if !cmp.Equal(receivedLabels, node.Labels) {
		t.Fatalf(cmp.Diff(receivedLabels, node.Labels))
	}

	receivedAdvs = <-advertisementChan
	if !cmp.Equal(receivedAdvs, advs) {
		t.Fatalf(cmp.Diff(receivedAdvs, advs))
	}

	// Delete CiliumNode
	err = spkr.OnDeleteCiliumNode(&node, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Withdrawal is represented as an empty list of advertisements
	receivedAdvs = <-advertisementChan
	if !cmp.Equal(len(receivedAdvs), 0) {
		t.Fatalf(cmp.Diff(len(receivedAdvs), 0))
	}
}
