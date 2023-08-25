// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metallbk8s "go.universe.tf/metallb/pkg/k8s"
	mlbk8s "go.universe.tf/metallb/pkg/k8s"
	"go.universe.tf/metallb/pkg/k8s/types"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/bgp/mock"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	DefaultTimeout = 30 * time.Second
)

var (
	errTimeout = errors.New("timeout occurred before mock received event")
	emptyEps   = mlbk8s.EpsOrSlices{
		Type: metallbk8s.Eps,
	}
)

// TestManagerEventNoService confirms when the
// manager is provided a service which does not exist
// in the local service cache it plumbs the
// correct call to the MetalLB Controller.
func TestManagerEventNoService(t *testing.T) {
	service, _, _, serviceID := mock.GenTestServicePairs()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	var rr struct {
		lock.Mutex
		name  string
		srvRo *v1.Service
		eps   mlbk8s.EpsOrSlices
	}

	mockCtrl := &mock.MockMetalLBController{
		SetBalancer_: func(name string, srvRo *v1.Service, eps mlbk8s.EpsOrSlices) types.SyncState {
			rr.Lock()
			rr.name, rr.srvRo, rr.eps = name, srvRo, eps
			rr.Unlock()
			cancel()
			return types.SyncStateSuccess
		},
	}

	// in this text return false indicating the service does not
	// exist
	mockIndexer := &mock.MockIndexer{
		GetByKey_: func(key string) (item interface{}, exists bool, err error) {
			return nil, false, nil
		},
	}

	mgr := &Manager{
		controller: mockCtrl,
		queue:      workqueue.New(),
		indexer:    mockIndexer,
	}

	go mgr.run()

	err := mgr.OnAddService(&service)
	if err != nil {
		t.Fatalf("OnAddService call failed: %v", err)
	}

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(errTimeout)
	}

	rr.Lock()
	defer rr.Unlock()

	if !cmp.Equal(rr.name, serviceID.String()) {
		t.Fatalf(cmp.Diff(rr.name, serviceID.String()))
	}
	if rr.srvRo != nil {
		t.Fatalf("expected srvRo to be nil")
	}
	if !cmp.Equal(rr.eps, emptyEps) {
		t.Fatalf(cmp.Diff(rr.eps, serviceID))
	}

}

// TestManagerEvent confirms the Manager
// performs the correct actions when an
// event occurs.
//
// This code path effectively tests all event handling paths
// since all events lead to a call to manager.process on the
// happy path.
func TestManagerEvent(t *testing.T) {
	service, v1Service, _, serviceID := mock.GenTestServicePairs()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	var rr struct {
		lock.Mutex
		name  string
		srvRo *v1.Service
		eps   mlbk8s.EpsOrSlices
	}

	mockCtrl := &mock.MockMetalLBController{
		SetBalancer_: func(name string, srvRo *v1.Service, eps mlbk8s.EpsOrSlices) types.SyncState {
			rr.Lock()
			rr.name, rr.srvRo, rr.eps = name, srvRo, eps
			rr.Unlock()
			cancel()
			return types.SyncStateSuccess
		},
	}

	mockIndexer := &mock.MockIndexer{
		GetByKey_: func(key string) (item interface{}, exists bool, err error) {
			return &service, true, nil
		},
	}

	mgr := &Manager{
		controller: mockCtrl,
		queue:      workqueue.New(),
		indexer:    mockIndexer,
	}

	go mgr.run()

	err := mgr.OnAddService(&service)
	if err != nil {
		t.Fatalf("OnAddService call failed: %v", err)
	}

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(errTimeout)
	}

	rr.Lock()
	defer rr.Unlock()

	if !cmp.Equal(rr.name, serviceID.String()) {
		t.Fatalf(cmp.Diff(rr.name, serviceID.String()))
	}
	if !cmp.Equal(rr.srvRo, &v1Service) {
		t.Fatalf(cmp.Diff(rr.srvRo, &v1Service))
	}
	if !cmp.Equal(rr.eps, emptyEps) {
		t.Fatalf(cmp.Diff(rr.eps, emptyEps))
	}
}
