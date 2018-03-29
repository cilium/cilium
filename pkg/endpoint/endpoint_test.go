// Copyright 2016-2017 Authors of Cilium
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

package endpoint

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api/v3"

	. "gopkg.in/check.v1"
)

var (
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointSuite struct{}

var _ = Suite(&EndpointSuite{})

func (s *EndpointSuite) TestEndpointID(c *C) {
	e := Endpoint{
		ID:     IPv6Addr.EndpointID(),
		IPv6:   IPv6Addr,
		IPv4:   IPv4Addr,
		Status: NewEndpointStatus(),
	}
	c.Assert(e.ID, Equals, uint16(4370)) //"0x1112"
	c.Assert(bytes.Compare(e.IPv6, IPv6Addr) == 0, Equals, true)
	c.Assert(bytes.Compare(e.IPv4, IPv4Addr) == 0, Equals, true)
}

func (s *EndpointSuite) TestOrderEndpointAsc(c *C) {
	eps := []*models.Endpoint{
		{ID: 5},
		{ID: 1000},
		{ID: 1},
		{ID: 3},
		{ID: 2},
	}
	epsWant := []*models.Endpoint{
		{ID: 1},
		{ID: 2},
		{ID: 3},
		{ID: 5},
		{ID: 1000},
	}
	OrderEndpointAsc(eps)
	c.Assert(eps, comparator.DeepEquals, epsWant)
}

func (s *EndpointSuite) TestEndpointStatus(c *C) {
	eps := NewEndpointStatus()

	c.Assert(eps.String(), Equals, "OK")

	sts := &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "BPF Program compiled",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "OK")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "BPF Program failed to compile",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	// An OK message with priority Other can't hide a High Failure message.
	for i := 0; i <= maxLogs; i++ {
		st := &statusLogMsg{
			Status: Status{
				Code: OK,
				Msg:  "Other thing compiled",
				Type: Other,
			},
			Timestamp: time.Now(),
		}
		eps.addStatusLog(st)
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "BPF Program compiled",
			Type: BPF,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	// BPF might be ok but the policy is still in fail mode.
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: Failure,
			Msg:  "Policy failed",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "Failure")

	sts = &statusLogMsg{
		Status: Status{
			Code: OK,
			Msg:  "Policy compiled",
			Type: Policy,
		},
		Timestamp: time.Now(),
	}
	eps.addStatusLog(sts)
	c.Assert(eps.String(), Equals, "OK")
}

func (s *EndpointSuite) TestEndpointState(c *C) {
	e := Endpoint{
		ID:     IPv6Addr.EndpointID(),
		IPv6:   IPv6Addr,
		IPv4:   IPv4Addr,
		Status: NewEndpointStatus(),
	}
	e.Mutex.Lock()
	e.SetDefaultOpts(nil)
	defer e.Mutex.Unlock()

	e.state = StateCreating
	c.Assert(e.SetStateLocked(StateCreating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, true)
	e.state = StateCreating
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, true)
	e.state = StateCreating
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, false)

	e.state = StateWaitingForIdentity
	c.Assert(e.SetStateLocked(StateCreating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, true)
	e.state = StateWaitingForIdentity
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, true)
	e.state = StateWaitingForIdentity
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, false)

	e.state = StateReady
	c.Assert(e.SetStateLocked(StateCreating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, true)
	e.state = StateReady
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, true)
	e.state = StateReady
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, false)

	e.state = StateWaitingToRegenerate
	c.Assert(e.SetStateLocked(StateCreating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, true)
	e.state = StateWaitingToRegenerate
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, false)

	e.state = StateRegenerating
	c.Assert(e.SetStateLocked(StateCreating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, true)
	e.state = StateRegenerating
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, true)
	e.state = StateRegenerating
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, false)

	e.state = StateDisconnecting
	c.Assert(e.SetStateLocked(StateCreating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, true)

	e.state = StateDisconnected
	c.Assert(e.SetStateLocked(StateCreating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, false)

	// Builder-specific transitions
	e.state = StateWaitingToRegenerate
	// Builder can't transition to ready from waiting-to-regenerate
	// as (another) build is pending
	c.Assert(e.BuilderSetStateLocked(StateReady, "test"), Equals, false)
	// Only builder knows when bpf regeneration starts
	c.Assert(e.SetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.BuilderSetStateLocked(StateRegenerating, "test"), Equals, true)
	// Builder does not trigger the need for regeneration
	c.Assert(e.BuilderSetStateLocked(StateWaitingToRegenerate, "test"), Equals, false)
	// Builder transitions to ready state after build is done
	c.Assert(e.BuilderSetStateLocked(StateReady, "test"), Equals, true)

	// Typical lifecycle
	e.state = StateCreating
	c.Assert(e.SetStateLocked(StateWaitingForIdentity, "test"), Equals, true)
	// Initial build does not change the state
	c.Assert(e.BuilderSetStateLocked(StateRegenerating, "test"), Equals, false)
	c.Assert(e.BuilderSetStateLocked(StateReady, "test"), Equals, false)
	// identity arrives
	c.Assert(e.SetStateLocked(StateReady, "test"), Equals, true)
	// a build is triggered after the identity is set
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, true)
	// build starts
	c.Assert(e.BuilderSetStateLocked(StateRegenerating, "test"), Equals, true)
	// another change arrives while building
	c.Assert(e.SetStateLocked(StateWaitingToRegenerate, "test"), Equals, true)
	// Builder's transition to ready fails due to the queued build
	c.Assert(e.BuilderSetStateLocked(StateReady, "test"), Equals, false)
	// second build starts
	c.Assert(e.BuilderSetStateLocked(StateRegenerating, "test"), Equals, true)
	// second build finishes
	c.Assert(e.BuilderSetStateLocked(StateReady, "test"), Equals, true)
	// endpoint is being deleted
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, true)
	// parallel disconnect fails
	c.Assert(e.SetStateLocked(StateDisconnecting, "test"), Equals, false)
	c.Assert(e.SetStateLocked(StateDisconnected, "test"), Equals, true)
}

func (s *EndpointSuite) TestWaitForPolicyRevision(c *C) {
	e := &Endpoint{policyRevision: 0}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1*time.Second))

	<-e.WaitForPolicyRevision(ctx, 0)
	// shouldn't get a timeout when waiting for policy revision already reached
	c.Assert(ctx.Err(), IsNil)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithTimeout(context.Background(), time.Duration(1*time.Second))

	<-e.WaitForPolicyRevision(ctx, 0)
	// shouldn't get a timeout when waiting for policy revision already reached
	c.Assert(ctx.Err(), IsNil)

	cancel()

	e.policyRevision = 1

	ctx, cancel = context.WithCancel(context.Background())

	ch := e.WaitForPolicyRevision(ctx, 2)
	cancel()
	// context was prematurely closed on purpose the error should be nil
	c.Assert(ctx.Err(), Equals, context.Canceled)

	e.setPolicyRevision(3)

	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since the wanted policy revision was reached")
	}

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)

	e.state = StateDisconnected

	ctx, cancel = context.WithCancel(context.Background())
	ch = e.WaitForPolicyRevision(ctx, 99)
	cancel()
	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since the endpoint is in disconnected state")
	}

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)

	e.state = StateCreating
	ctx, cancel = context.WithCancel(context.Background())
	ch = e.WaitForPolicyRevision(ctx, 99)

	e.cleanPolicySignals()

	select {
	case <-ch:
	default:
		c.Fatalf("channel should have been closed since all policy signals were closed")
	}
	cancel()

	// Number of policy revision signals should be 0
	c.Assert(len(e.policyRevisionSignals), Equals, 0)
}

func (s *EndpointSuite) TestProxyID(c *C) {
	e := &Endpoint{ID: 123, policyRevision: 0}

	id := e.ProxyID(&policy.L4Filter{Port: 8080, Protocol: v3.ProtoTCP, Ingress: true})
	endpointID, ingress, protocol, port, err := policy.ParseProxyID(id)
	c.Assert(endpointID, Equals, uint16(123))
	c.Assert(ingress, Equals, true)
	c.Assert(protocol, Equals, "TCP")
	c.Assert(port, Equals, uint16(8080))
	c.Assert(err, IsNil)
}
