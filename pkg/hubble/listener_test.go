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

package hubble

import (
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	listener2 "github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/server"
	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type HubbleSuite struct{}

var _ = Suite(&HubbleSuite{})

func (s *HubbleSuite) TestHubbleListener(c *C) {
	// Setting maxFlows to 100. This should create the events channel with buffer size set to 1:
	//   https://github.com/cilium/hubble/blob/04ab72591faca62a305ce0715108876167182e04/pkg/server/local_observer.go#L90
	grpcServer := server.NewLocalServer(nil, 100, logrus.NewEntry(logrus.New()))
	listener := NewHubbleListener(grpcServer)
	c.Assert(listener.Version(), Equals, listener2.Version1_2)
	pl := payload.Payload{CPU: 1, Lost: 2, Type: 3, Data: []byte{'a', 'b', 'c'}}
	listener.Enqueue(&pl)
	// The second enqueue fails because the event channel is full, but it shouldn't block.
	listener.Enqueue(&pl)
	received := <-grpcServer.GetEventsChannel()
	c.Assert(received.CPU, Equals, int32(pl.CPU))
	c.Assert(received.Lost, Equals, pl.Lost)
	c.Assert(received.Type, Equals, flow.EventType(pl.Type))
	c.Assert(received.Data, checker.DeepEquals, pl.Data)
	c.Assert(received.HostName, Equals, node.GetName())
	// Verify that the events channel is empty now.
	select {
	case ev := <-grpcServer.GetEventsChannel():
		c.Error("Unexpected event", ev)
	default:
	}
}
