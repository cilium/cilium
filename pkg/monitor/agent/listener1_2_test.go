// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/monitor/agent/listener"
)

func TestListenerv1_2(t *testing.T) {
	closed := make(chan bool)
	server, client := net.Pipe()
	logger := hivetest.Logger(t)
	l := newListenerv1_2(logger, client, 10, func(listener listener.MonitorListener) {
		closed <- true
	})
	// Verify the listener version.
	require.Equal(t, listener.Version1_2, l.Version())
	// Calling Close() multiple times shouldn't cause panic.
	l.Close()
	l.Close()
	// Make sure the cleanup function gets called.
	<-closed
	server.Close()
}
