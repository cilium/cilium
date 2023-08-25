// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net"
	"testing"

	. "github.com/cilium/checkmate"

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
