// Copyright 2018-2019 Authors of Cilium
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

// +build !privileged_tests

package endpointmanager

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/testutils/allocator"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointManagerSuite struct {
	repo *policy.Repository
}

var _ = Suite(&EndpointManagerSuite{})

func (s *EndpointManagerSuite) SetUpSuite(c *C) {
	s.repo = policy.NewPolicyRepository(nil, nil)
}

func (s *EndpointManagerSuite) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s *EndpointManagerSuite) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, wg *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	return 0, nil, nil, nil
}

func (s *EndpointManagerSuite) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

func (s *EndpointManagerSuite) UpdateNetworkPolicy(e regeneration.EndpointUpdater, policy *policy.L4Policy,
	proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	return nil, nil
}

func (s *EndpointManagerSuite) RemoveNetworkPolicy(e regeneration.EndpointInfoSource) {}

func (s *EndpointManagerSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *EndpointManagerSuite) GetCompilationLock() *lock.RWMutex {
	return nil
}

func (s *EndpointManagerSuite) SendNotification(typ monitorAPI.AgentNotification, text string) error {
	return nil
}

func (s *EndpointManagerSuite) Datapath() datapath.Datapath {
	return nil
}

type DummyRuleCacheOwner struct{}

func (d *DummyRuleCacheOwner) ClearPolicyConsumers(id uint16) *sync.WaitGroup {
	return &sync.WaitGroup{}
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration) {
}

func (s *EndpointManagerSuite) TestLookup(c *C) {
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
	mgr := NewEndpointManager(&dummyEpSyncher{})
	type args struct {
		id string
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name:       "endpoint does not exist",
			preTestRun: func() {},
			setupArgs: func() args {
				return args{
					"1234",
				}
			},
			setupWant: func() want {
				return want{
					ep:       nil,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {},
		},
		{
			name: "endpoint by cilium local ID",
			preTestRun: func() {
				ep.ID = 1234
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewCiliumID(1234),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.ID = 0
			},
		},
		{
			name: "endpoint by cilium global ID",
			preTestRun: func() {
				ep.ID = 1234
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.CiliumGlobalIdPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					err:      ErrUnsupportedID,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.ID = 0
			},
		},
		{
			name: "endpoint by container ID",
			preTestRun: func() {
				ep.SetContainerID("1234")
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerIdPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetContainerID("")
			},
		},
		{
			name: "endpoint by docker endpoint ID",
			preTestRun: func() {
				ep.SetDockerEndpointID("1234")
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.DockerEndpointPrefix, "1234"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetDockerEndpointID("")
			},
		},
		{
			name: "endpoint by container name",
			preTestRun: func() {
				ep.SetContainerName("foo")
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.ContainerNamePrefix, "foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetContainerName("")
			},
		},
		{
			name: "endpoint by pod name",
			preTestRun: func() {
				ep.SetK8sNamespace("default")
				ep.SetK8sPodName("foo")
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.PodNamePrefix, "default/foo"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.SetK8sPodName("")
			},
		},
		{
			name: "endpoint by ipv4",
			preTestRun: func() {
				ipv4, err := addressing.NewCiliumIPv4("127.0.0.1")
				ep.IPv4 = ipv4
				c.Assert(err, IsNil)
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.IPv4Prefix, "127.0.0.1"),
				}
			},
			setupWant: func() want {
				return want{
					ep:       ep,
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 10, endpoint.StateReady)
				ep.IPv4 = nil
			},
		},
		{
			name: "invalid ID",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID("foo", "bar"),
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
			postTestRun: func() {
			},
		},
		{
			name: "invalid cilium ID",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					endpointid.NewID(endpointid.CiliumLocalIdPrefix, "bar"),
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got, err := mgr.Lookup(args.id)
		c.Assert(err, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupCiliumID(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 2, endpoint.StateReady)
	type args struct {
		id uint16
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "existing cilium ID",
			preTestRun: func() {
				ep.ID = 1
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					1,
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.ID = 0
			},
		},
		{
			name: "non-existing cilium ID",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					1,
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupCiliumID(args.id)
		exists := mgr.EndpointExists(args.id)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		c.Assert(exists, checker.Equals, want.ep != nil, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupContainerID(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 3, endpoint.StateReady)
	type args struct {
		id string
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "existing container ID",
			preTestRun: func() {
				ep.SetContainerID("foo")
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.SetContainerID("")
			},
		},
		{
			name: "non-existing container ID",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupContainerID(args.id)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupIPv4(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 4, endpoint.StateReady)
	type args struct {
		ip string
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "existing LookupIPv4",
			preTestRun: func() {
				ip, err := addressing.NewCiliumIPv4("127.0.0.1")
				c.Assert(err, IsNil)
				ep.IPv4 = ip
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					"127.0.0.1",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.IPv4 = nil
			},
		},
		{
			name: "non-existing LookupIPv4",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"127.0.0.1",
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupIPv4(args.ip)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupPodName(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 5, endpoint.StateReady)
	type args struct {
		podName string
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "existing PodName",
			preTestRun: func() {
				ep.SetK8sNamespace("default")
				ep.SetK8sPodName("foo")
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.IPv4 = nil
			},
		},
		{
			name: "non-existing PodName",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"default/foo",
				}
			},
			setupWant: func() want {
				return want{
					ep: nil,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.LookupPodName(args.podName)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestUpdateReferences(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 6, endpoint.StateReady)
	type args struct {
		ep *endpoint.Endpoint
	}
	type want struct {
		ep       *endpoint.Endpoint
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Updating all references",
			preTestRun: func() {
				ep.ID = 1
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				// Update endpoint before running test
				ep.SetK8sNamespace("default")
				ep.SetK8sPodName("foo")
				ep.SetContainerID("container")
				ep.SetDockerEndpointID("dockerendpointID")
				ip, err := addressing.NewCiliumIPv4("127.0.0.1")
				c.Assert(err, IsNil)
				ep.IPv4 = ip
				ep.SetContainerName("containername")
				return args{
					ep: ep,
				}
			},
			setupWant: func() want {
				return want{
					ep: ep,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep.SetK8sNamespace("")
				ep.SetK8sPodName("")
				ep.SetContainerID("")
				ep.SetDockerEndpointID("")
				ep.IPv4 = nil
				ep.SetContainerName("")
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		args.ep.UpdateReferences(mgr)

		ep = mgr.LookupContainerID(want.ep.GetContainerID())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerEndpoint(want.ep.GetDockerEndpointID())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupIPv4(want.ep.IPv4.String())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.lookupDockerContainerName(want.ep.GetContainerName())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = mgr.LookupPodName(want.ep.GetK8sNamespaceAndPodName())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestRemove(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 7, endpoint.StateReady)
	type args struct {
	}
	type want struct {
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Updating all references",
			preTestRun: func() {
				ep.ID = 1
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{}
			},
			setupWant: func() want {
				return want{}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()

		mgr.RemoveAll()
		c.Assert(len(mgr.endpoints), Equals, 0, Commentf("Test Name: %s", tt.name))
		c.Assert(len(mgr.endpointsAux), Equals, 0, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestHasGlobalCT(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 1, endpoint.StateReady)
	type args struct {
		ep *endpoint.Endpoint
	}
	type want struct {
		result bool
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Endpoint with Conntrack global",
			preTestRun: func() {
				ep.ID = 1
				ep.Options = option.NewIntOptions(&endpoint.EndpointMutableOptionLibrary)
				ep.Expose(mgr)
			},
			setupWant: func() want {
				return want{
					result: true,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 1, endpoint.StateReady)
				ep.ID = 0
				ep.Options = nil
			},
		},
		{
			name: "Endpoint with Conntrack local",
			preTestRun: func() {
				ep.ID = 1
				ep.Options = option.NewIntOptions(&endpoint.EndpointMutableOptionLibrary)
				ep.Options.SetIfUnset(option.ConntrackLocal, option.OptionEnabled)
				ep.Expose(mgr)
			},
			setupWant: func() want {
				return want{
					result: false,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 1, endpoint.StateReady)
				ep.ID = 0
				ep.Options = nil
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		want := tt.setupWant()
		got := mgr.HasGlobalCT()
		c.Assert(got, checker.DeepEquals, want.result, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestWaitForEndpointsAtPolicyRev(c *C) {
	mgr := NewEndpointManager(&dummyEpSyncher{})
	ep := endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 1, endpoint.StateReady)
	type args struct {
		ctx    context.Context
		rev    uint64
		cancel context.CancelFunc
	}
	type want struct {
		err      error
		errCheck Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "Endpoint with revision already set",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(5)
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				return args{
					ctx: context.Background(),
					rev: 5,
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Equals,
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 1, endpoint.StateReady)
			},
		},
		{
			name: "Context already timed out",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(5)
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				ctx, cancel := context.WithTimeout(context.Background(), 0)
				return args{
					ctx:    ctx,
					rev:    5,
					cancel: cancel,
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 1, endpoint.StateReady)
			},
		},
		{
			name: "Revision is will never be set to the waiting revision",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(4)
				ep.Expose(mgr)
			},
			setupArgs: func() args {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				return args{
					ctx:    ctx,
					rev:    5,
					cancel: cancel,
				}
			},
			setupWant: func() want {
				return want{
					err:      nil,
					errCheck: Not(Equals),
				}
			},
			postTestRun: func() {
				mgr.WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, 1, endpoint.StateReady)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := mgr.WaitForEndpointsAtPolicyRev(args.ctx, args.rev)
		c.Assert(got, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		if args.cancel != nil {
			args.cancel()
		}
		tt.postTestRun()
	}
}
