// Copyright 2016-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mock

import (
	"github.com/cilium/cilium/pkg/k8s"

	"go.universe.tf/metallb/pkg/bgp"
	metallbk8s "go.universe.tf/metallb/pkg/k8s"
	"go.universe.tf/metallb/pkg/k8s/types"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
	v1 "k8s.io/api/core/v1"
)

// MockMetalLBSpeaker implements the speaker.Speaker interface by delegating to
// a set of functions defined during test.
type MockMetalLBSpeaker struct {
	SetService_    func(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState
	SetNodeLabels_ func(labels map[string]string) types.SyncState
	PeerSession_   func() []metallbspr.Session
}

func (m *MockMetalLBSpeaker) SetService(name string, svc *metallbspr.Service, eps *metallbspr.Endpoints) types.SyncState {
	return m.SetService_(name, svc, eps)
}

func (m *MockMetalLBSpeaker) SetNodeLabels(labels map[string]string) types.SyncState {
	return m.SetNodeLabels_(labels)
}

func (m *MockMetalLBSpeaker) PeerSessions() []metallbspr.Session {
	return m.PeerSession_()
}

// MockEndpointGetter implements the method set for obtaining th endpoints
// of a Service.
type MockEndpointGetter struct {
	GetEndpointsOfService_ func(svcID k8s.ServiceID) *k8s.Endpoints
}

func (m *MockEndpointGetter) GetEndpointsOfService(svcID k8s.ServiceID) *k8s.Endpoints {
	return m.GetEndpointsOfService_(svcID)
}

// MockSession implements the metallbspr.Session interface and is useful
// when utilizing the PeerSession() method of a MockMetalLBSpeaker.
type MockSession struct {
	Set_ func(advs ...*bgp.Advertisement) error
}

func (m *MockSession) Set(advs ...*bgp.Advertisement) error {
	return m.Set_(advs...)
}

// Close is a no-op
func (m *MockSession) Close() error {
	return nil
}

// MockMetalLBController implements the manager.Controller interface by delegating to
// a set of functions defined during test.
type MockMetalLBController struct {
	SetBalancer_ func(name string, srvRo *v1.Service, eps metallbk8s.EpsOrSlices) types.SyncState
	MarkSynced_  func()
}

func (m *MockMetalLBController) SetBalancer(name string, srvRo *v1.Service, eps metallbk8s.EpsOrSlices) types.SyncState {
	return m.SetBalancer_(name, srvRo, eps)
}

func (m *MockMetalLBController) MarkSynced() {
	m.MarkSynced_()
}

// MockIndexer implements the cache.Store interface
// from the k8s.io/client-go/cache package
//
// The BGP package only utilizes two methods from this
// interface thus our mock is terse.
type MockIndexer struct {
	GetByKey_ func(key string) (item interface{}, exists bool, err error)
	ListKeys_ func() []string
}

func (m *MockIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	return m.GetByKey_(key)
}

func (m *MockIndexer) ListKeys() []string {
	return m.ListKeys_()
}

func (m *MockIndexer) Add(obj interface{}) error {
	panic("not implemented")
}

func (m *MockIndexer) Update(obj interface{}) error {
	panic("not implemented")
}

func (m *MockIndexer) Delete(obj interface{}) error {
	panic("not implemented")
}

func (m *MockIndexer) List() []interface{} {
	panic("not implemented")
}

func (m *MockIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	panic("not implemented")
}

func (m *MockIndexer) Replace([]interface{}, string) error {
	panic("not implemented")
}

func (m *MockIndexer) Resync() error {
	panic("not implemented")
}
