// Copyright 2018-2020 Authors of Cilium
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

package agent

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/monitor/agent/listener"
)

func Test(t *testing.T) { TestingT(t) }

type ListenerSuite struct{}

var _ = Suite(&ListenerSuite{})

func (m *ListenerSuite) TestListenerv1_2(c *C) {
	closed := make(chan bool)
	server, client := net.Pipe()
	l := newListenerv1_2(client, 10, func(listener listener.MonitorListener) {
		closed <- true
	})
	// Verify the listener version.
	c.Assert(l.Version(), Equals, listener.Version1_2)
	// Calling Close() multiple times shouldn't cause panic.
	l.Close()
	l.Close()
	// Make sure the cleanup function gets called.
	<-closed
	server.Close()
}
