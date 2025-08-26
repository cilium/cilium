// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/source"
)

func TestFakeIPCache(t *testing.T) {
	ipcacheMock := NewIPCache(true)

	ipcacheMock.Upsert("1.1.1.1", net.ParseIP("2.2.2.2"), 0, nil, ipcache.Identity{ID: 1, Source: source.Local})
	select {
	case event := <-ipcacheMock.Events:
		require.Equal(t, NodeEvent{EventUpsert, net.ParseIP("1.1.1.1")}, event)
	case <-time.After(5 * time.Second):
		t.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	ipcacheMock.Delete("1.1.1.1", source.Local)

	select {
	case event := <-ipcacheMock.Events:
		require.Equal(t, NodeEvent{EventDelete, net.ParseIP("1.1.1.1")}, event)
	case <-time.After(5 * time.Second):
		t.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}
}
