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
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointManagerSuite struct {
	repo *policy.Repository
}

var _ = Suite(&EndpointManagerSuite{repo: policy.NewPolicyRepository()})

type DummyRuleCacheOwner struct{}

func (d *DummyRuleCacheOwner) ClearPolicyConsumers(id uint16) *sync.WaitGroup {
	return &sync.WaitGroup{}
}

func (s *EndpointManagerSuite) TestLookup(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 10, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep.ID = 0
			},
		},
		{
			name: "endpoint by cilium global ID",
			preTestRun: func() {
				ep.ID = 1234
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep.ID = 0
			},
		},
		{
			name: "endpoint by container ID",
			preTestRun: func() {
				ep.ContainerID = "1234"
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep.ContainerID = ""
			},
		},
		{
			name: "endpoint by docker endpoint ID",
			preTestRun: func() {
				ep.DockerEndpointID = "1234"
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep.DockerEndpointID = ""
			},
		},
		{
			name: "endpoint by container name",
			preTestRun: func() {
				ep.ContainerName = "foo"
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep.ContainerName = ""
			},
		},
		{
			name: "endpoint by pod name",
			preTestRun: func() {
				ep.SetK8sNamespace("default")
				ep.SetK8sPodName("foo")
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep.SetK8sPodName("")
			},
		},
		{
			name: "endpoint by ipv4",
			preTestRun: func() {
				ipv4, err := addressing.NewCiliumIPv4("127.0.0.1")
				ep.IPv4 = ipv4
				c.Assert(err, IsNil)
				Insert(ep)
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
				WaitEndpointRemoved(ep)
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
		got, err := Lookup(args.id)
		c.Assert(err, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupCiliumID(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 2, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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
				WaitEndpointRemoved(ep)
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
		got := LookupCiliumID(args.id)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupContainerID(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 3, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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
				WaitEndpointRemoved(ep)
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
		got := LookupContainerID(args.id)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupIPv4(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 4, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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
				WaitEndpointRemoved(ep)
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
		got := LookupIPv4(args.ip)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestLookupPodName(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 5, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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
				WaitEndpointRemoved(ep)
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
		got := LookupPodName(args.podName)
		c.Assert(got, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestUpdateReferences(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 6, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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
				WaitEndpointRemoved(ep)
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
		UpdateReferences(args.ep)

		ep = LookupContainerID(want.ep.GetContainerID())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = lookupDockerEndpoint(want.ep.DockerEndpointID)
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = LookupIPv4(want.ep.IPv4.String())
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		ep = lookupDockerContainerName(want.ep.ContainerName)
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))

		want.ep.UnconditionalRLock()
		ep = LookupPodName(want.ep.GetK8sNamespaceAndPodNameLocked())
		want.ep.RUnlock()
		c.Assert(ep, checker.DeepEquals, want.ep, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestRemove(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 7, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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

		RemoveAll()
		c.Assert(len(endpoints), Equals, 0, Commentf("Test Name: %s", tt.name))
		c.Assert(len(endpointsAux), Equals, 0, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestHasGlobalCT(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 1, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
			},
			setupWant: func() want {
				return want{
					result: true,
				}
			},
			postTestRun: func() {
				WaitEndpointRemoved(ep)
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
				Insert(ep)
			},
			setupWant: func() want {
				return want{
					result: false,
				}
			},
			postTestRun: func() {
				WaitEndpointRemoved(ep)
				ep.ID = 0
				ep.Options = nil
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		want := tt.setupWant()
		got := HasGlobalCT()
		c.Assert(got, checker.DeepEquals, want.result, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *EndpointManagerSuite) TestWaitForEndpointsAtPolicyRev(c *C) {
	ep := endpoint.NewEndpointWithState(s.repo, 1, endpoint.StateReady)
	ep.UpdateLogger(nil)
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
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s.repo, 1, endpoint.StateReady)
			},
		},
		{
			name: "Context already timed out",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(5)
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s.repo, 1, endpoint.StateReady)
			},
		},
		{
			name: "Revision is will never be set to the waiting revision",
			preTestRun: func() {
				ep.ID = 1
				ep.SetPolicyRevision(4)
				Insert(ep)
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
				WaitEndpointRemoved(ep)
				ep = endpoint.NewEndpointWithState(s.repo, 1, endpoint.StateReady)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		got := WaitForEndpointsAtPolicyRev(args.ctx, args.rev)
		c.Assert(got, want.errCheck, want.err, Commentf("Test Name: %s", tt.name))
		if args.cancel != nil {
			args.cancel()
		}
		tt.postTestRun()
	}
}
