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
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

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
	e := Endpoint{IPv6: IPv6Addr, IPv4: IPv4Addr}
	e.SetID()
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
	c.Assert(eps, DeepEquals, epsWant)
}

func (s *EndpointSuite) TestDeepCopy(c *C) {
	ipv4, err := addressing.NewCiliumIPv4("127.0.0.1")
	c.Assert(err, IsNil)
	ipv6, err := addressing.NewCiliumIPv6("::1")
	c.Assert(err, IsNil)
	epWant := &Endpoint{
		ID:               12,
		DockerID:         "123",
		DockerNetworkID:  "1234",
		DockerEndpointID: "12345",
		IfName:           "lxcifname",
		LXCMAC:           mac.MAC{1, 2, 3, 4, 5, 6},
		IPv6:             ipv6,
		IPv4:             ipv4,
		IfIndex:          4,
		NodeMAC:          mac.MAC{1, 2, 3, 4, 5, 6},
		NodeIP:           net.ParseIP("192.168.0.1"),
		PortMap:          make([]PortMap, 2),
		Opts:             option.NewBoolOptions(&EndpointOptionLibrary),
		Status:           NewEndpointStatus(),
	}
	cpy := epWant.DeepCopy()
	c.Assert(*cpy, DeepEquals, *epWant)
	epWant.SecLabel = &policy.Identity{
		ID: 1,
		Labels: labels.Labels{
			"io.cilium.kubernetes": labels.NewLabel("io.cilium.kubernetes", "", "cilium"),
		},
		Endpoints: map[string]time.Time{
			"1234": time.Now(),
		},
	}
	epWant.Consumable = &policy.Consumable{
		ID:        123,
		Iteration: 3,
		Labels:    nil,
		LabelList: []*labels.Label{
			labels.NewLabel("io.cilium.kubernetes", "", "cilium"),
		},
		Maps: map[int]*policymap.PolicyMap{
			0: {},
		},
		Consumers: map[string]*policy.Consumer{
			"foo": policy.NewConsumer(12),
		},
		ReverseRules: map[policy.NumericIdentity]*policy.Consumer{
			12: policy.NewConsumer(12),
		},
	}
	epWant.PolicyMap = &policymap.PolicyMap{}
	cpy = epWant.DeepCopy()
	c.Assert(*cpy.SecLabel, DeepEquals, *epWant.SecLabel)
	c.Assert(*cpy.Consumable, DeepEquals, *epWant.Consumable)
	c.Assert(*cpy.PolicyMap, DeepEquals, *epWant.PolicyMap)

	epWant.Consumable.Labels = &policy.Identity{
		ID: 1,
		Labels: labels.Labels{
			"io.cilium.kubernetes": labels.NewLabel("io.cilium.kubernetes", "", "cilium"),
		},
		Endpoints: map[string]time.Time{
			"1234": time.Now(),
		},
	}

	epWant.PolicyMap = &policymap.PolicyMap{}
	cpy = epWant.DeepCopy()

	c.Assert(*cpy.Consumable.Labels, DeepEquals, *epWant.Consumable.Labels)

	cpy.Consumable.Labels.Endpoints["1234"] = time.Now()
	c.Assert(*cpy.Consumable.Labels, Not(DeepEquals), *epWant.Consumable.Labels)
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
