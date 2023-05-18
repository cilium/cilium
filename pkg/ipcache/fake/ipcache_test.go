// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"
	"testing"
	"time"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/source"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type fakeIPCacheSuite struct{}

var _ = check.Suite(&fakeIPCacheSuite{})

func (s *fakeIPCacheSuite) TestFakeIPCache(c *check.C) {
	ipcacheMock := NewIPCache(true)

	ipcacheMock.Upsert("1.1.1.1", net.ParseIP("2.2.2.2"), 0, nil, ipcache.Identity{ID: 1, Source: source.Local})
	select {
	case event := <-ipcacheMock.Events:
		c.Assert(event, checker.DeepEquals, NodeEvent{EventUpsert, net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	ipcacheMock.Delete("1.1.1.1", source.Local)

	select {
	case event := <-ipcacheMock.Events:
		c.Assert(event, checker.DeepEquals, NodeEvent{EventDelete, net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}
}
