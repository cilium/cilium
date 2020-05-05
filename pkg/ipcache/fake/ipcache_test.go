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

package fake

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/source"

	"gopkg.in/check.v1"
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
