// Copyright 2018 Authors of Cilium
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

package lbmap

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LBMapTestSuite struct{}

var _ = Suite(&LBMapTestSuite{})

func createBackend(c *C, ip string, port, revnat uint16) ServiceValue {
	i := net.ParseIP(ip)
	c.Assert(i, Not(IsNil))
	v := NewService4Value(0, i, port, revnat, 0)
	c.Assert(v, Not(IsNil))
	return v
}

func (b *LBMapTestSuite) TestScaleService(c *C) {
	ip := net.ParseIP("1.1.1.1")
	c.Assert(ip, Not(IsNil))
	frontend := NewService4Key(ip, 80, 0)

	svc := newBpfService(frontend)
	c.Assert(svc, Not(IsNil))

	b1 := createBackend(c, "2.2.2.2", 80, 1)
	svc.addBackend(b1)
	c.Assert(len(svc.backendsByMapIndex), Equals, 1)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b1)

	b2 := createBackend(c, "3.3.3.3", 80, 1)
	svc.addBackend(b2)
	c.Assert(len(svc.backendsByMapIndex), Equals, 2)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b1)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)

	svc.deleteBackend(b1)
	c.Assert(len(svc.backendsByMapIndex), Equals, 2)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)

	b3 := createBackend(c, "4.4.4.4", 80, 1)
	svc.addBackend(b3)
	c.Assert(len(svc.backendsByMapIndex), Equals, 3)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[2].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[3].bpfValue, Equals, b3)
	c.Assert(svc.backendsByMapIndex[3].isHole, Equals, false)

	b4 := createBackend(c, "5.5.5.5", 80, 1)
	svc.addBackend(b4)
	c.Assert(len(svc.backendsByMapIndex), Equals, 4)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[2].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[3].bpfValue, Equals, b3)
	c.Assert(svc.backendsByMapIndex[3].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[4].bpfValue, Equals, b4)
	c.Assert(svc.backendsByMapIndex[4].isHole, Equals, false)

	svc.deleteBackend(b4)
	c.Assert(len(svc.backendsByMapIndex), Equals, 4)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[3].bpfValue, Equals, b3)
	// b3 has less duplicates and must be used
	c.Assert(svc.backendsByMapIndex[4].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[4].bpfValue, Equals, b3)

	svc.deleteBackend(b3)
	c.Assert(len(svc.backendsByMapIndex), Equals, 4)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[1].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[2].isHole, Equals, false)
	c.Assert(svc.backendsByMapIndex[2].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[3].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[3].isHole, Equals, true)
	c.Assert(svc.backendsByMapIndex[4].bpfValue, Equals, b2)
	c.Assert(svc.backendsByMapIndex[4].isHole, Equals, true)

	// last backend is removed, we can finally remove all backend slots
	svc.deleteBackend(b2)
	c.Assert(len(svc.backendsByMapIndex), Equals, 0)

	svc.addBackend(b4)
	c.Assert(len(svc.backendsByMapIndex), Equals, 1)
	c.Assert(svc.backendsByMapIndex[1].bpfValue, Equals, b4)
}

func (b *LBMapTestSuite) TestPrepareUpdate(c *C) {
	cache := newLBMapCache()

	ip := net.ParseIP("1.1.1.1")
	c.Assert(ip, Not(IsNil))
	frontend := NewService4Key(ip, 80, 0)

	b1 := createBackend(c, "2.2.2.2", 80, 1)
	b2 := createBackend(c, "3.3.3.3", 80, 1)
	b3 := createBackend(c, "4.4.4.4", 80, 1)

	bpfSvc, _, _, _ := cache.prepareUpdate(frontend, []ServiceValue{b1, b2})
	c.Assert(bpfSvc.backendsByMapIndex[1].bpfValue, checker.DeepEquals, b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, checker.DeepEquals, b2)

	backends := bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 2)
	c.Assert(backends[0], checker.DeepEquals, b1)
	c.Assert(backends[1], checker.DeepEquals, b2)

	bpfSvc, _, _, _ = cache.prepareUpdate(frontend, []ServiceValue{b1, b2, b3})
	c.Assert(bpfSvc.backendsByMapIndex[1].bpfValue, checker.DeepEquals, b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, checker.DeepEquals, b2)
	c.Assert(bpfSvc.backendsByMapIndex[3].bpfValue, checker.DeepEquals, b3)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 3)
	c.Assert(backends[0], checker.DeepEquals, b1)
	c.Assert(backends[1], checker.DeepEquals, b2)
	c.Assert(backends[2], checker.DeepEquals, b3)

	bpfSvc, _, _, _ = cache.prepareUpdate(frontend, []ServiceValue{b2, b3})
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, Not(DeepEquals), b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, checker.DeepEquals, b2)
	c.Assert(bpfSvc.backendsByMapIndex[3].bpfValue, checker.DeepEquals, b3)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 3)
	c.Assert(backends[0], Not(DeepEquals), b1)
	c.Assert(backends[1], checker.DeepEquals, b2)
	c.Assert(backends[2], checker.DeepEquals, b3)

	bpfSvc, _, _, _ = cache.prepareUpdate(frontend, []ServiceValue{b1, b2, b3})
	c.Assert(bpfSvc.backendsByMapIndex[1].bpfValue, Not(DeepEquals), b1)
	c.Assert(bpfSvc.backendsByMapIndex[2].bpfValue, checker.DeepEquals, b2)
	c.Assert(bpfSvc.backendsByMapIndex[3].bpfValue, checker.DeepEquals, b3)
	c.Assert(bpfSvc.backendsByMapIndex[4].bpfValue, checker.DeepEquals, b1)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 4)
	c.Assert(backends[0], Not(DeepEquals), b1)
	c.Assert(backends[1], checker.DeepEquals, b2)
	c.Assert(backends[2], checker.DeepEquals, b3)
	c.Assert(backends[3], checker.DeepEquals, b1)

	bpfSvc, _, _, _ = cache.prepareUpdate(frontend, []ServiceValue{})
	c.Assert(len(bpfSvc.backendsByMapIndex), Equals, 0)

	backends = bpfSvc.getBackends()
	c.Assert(len(backends), Equals, 0)
}

func (b *LBMapTestSuite) TestGetBackends(c *C) {
	b1 := NewService4Value(1, net.ParseIP("2.2.2.2"), 80, 1, 0)
	b2 := NewService4Value(2, net.ParseIP("1.1.1.1"), 80, 1, 0)

	svc := bpfService{}
	c.Assert(len(svc.getBackends()), Equals, 0)

	svc = bpfService{
		backendsByMapIndex: map[int]*bpfBackend{
			1: {id: "1", isHole: true, bpfValue: b1},
		},
	}

	backends := svc.getBackends()
	c.Assert(len(backends), Equals, 1)
	c.Assert(backends[0], checker.DeepEquals, b1)

	svc = bpfService{
		backendsByMapIndex: map[int]*bpfBackend{
			1: {id: "1", isHole: true, bpfValue: b1},
			2: {id: "2", isHole: false, bpfValue: b2},
		},
	}

	backends = svc.getBackends()
	c.Assert(len(backends), Equals, 2)
	c.Assert(backends[0], checker.DeepEquals, b1)
	c.Assert(backends[1], checker.DeepEquals, b2)
}
