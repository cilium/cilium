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

// +build privileged_tests

package lbmap

import (
	"bytes"
	"encoding/json"
	"github.com/cilium/cilium/pkg/bpf"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	. "gopkg.in/check.v1"
	"net"
	"os"
	"testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LbMaglevTestSuite struct{ *LBMaglevMap }

var _ = Suite(&LbMaglevTestSuite{})

func (e *LbMaglevTestSuite) SetUpTest(c *C) {
	MaglevRingMapName = "unit_test_lb_maglev_ring"
	innerMapName = "unit_test_lb_maglev_ring_inner_map"
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)
	err = CreateMaglevRingMap()
	c.Assert(err, IsNil)
	e.LBMaglevMap, err = NewMaglevMap(DefaultMaglevRingSize)
	c.Assert(err, IsNil)
	for _, m := range []*bpf.Map{Service4MapV2, Backend4Map, RevNat4Map} {
		_, err = m.OpenOrCreate()
		c.Assert(err, IsNil)
		_ = m.DeleteAll()
	}
}

func (e *LbMaglevTestSuite) TearDownTest(c *C) {
	e.LBMaglevMap.Destruct()
	CloseMaglevRingMap()
	_ = os.Remove(MaglevRingMapName)
	_ = os.Remove(innerMapName)
}

var (
	testFrontend1 = lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.1"), 80, 1)
	testFrontend2 = lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.2"), 80, 2)

	testBackend1 = lb.NewBackend(1, lb.TCP, net.ParseIP("10.0.0.1"), 8080)
	testBackend2 = lb.NewBackend(2, lb.TCP, net.ParseIP("10.0.0.2"), 8080)
	testBackend3 = lb.NewBackend(3, lb.TCP, net.ParseIP("10.0.0.3"), 8080)

	testSvc1 = &lb.SVC{
		Frontend: *testFrontend1,
		Backends: []lb.Backend{
			*testBackend1,
			*testBackend2,
		},
		Type:                lb.SVCTypeNodePort,
		TrafficPolicy:       lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: 0,
		Name:                "svc1",
		Namespace:           "ns1",
	}

	testSvc2 = &lb.SVC{
		Frontend: *testFrontend2,
		Backends: []lb.Backend{
			*testBackend2,
			*testBackend3,
		},
		Type:                lb.SVCTypeNodePort,
		TrafficPolicy:       lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: 0,
		Name:                "svc2",
		Namespace:           "ns2",
	}

	testSvcs = []*lb.SVC{
		testSvc1,
		testSvc2,
	}
)

func (e *LbMaglevTestSuite) checkService(testSvcs []*lb.SVC, c *C) {
	realSvcs, errs := e.DumpServiceMaps()
	c.Assert(len(errs), Equals, 0)
	c.Assert(len(realSvcs), Equals, len(testSvcs))

	for i, conf := range testSvcs {
		svc := realSvcs[i]
		svcJ, _ := json.MarshalIndent(svc, "", " ")
		confJ, _ := json.MarshalIndent(conf, "", " ")

		if bytes.Equal(svcJ, confJ) {
			c.Fatalf("svc %s\nconf %s\n", string(svcJ), string(confJ))
		}
	}
}

func (e *LbMaglevTestSuite) TestUpsertAndDeleteService(c *C) {
	bpf.CheckOrMountFS("", false)

	// add all
	for _, svc := range testSvcs {
		fe := &svc.Frontend
		bes := []*lb.BackendMeta{}
		for _, be := range svc.Backends {
			err := e.AddBackend(uint16(be.ID), be.IP, be.Port, false)
			c.Assert(err, IsNil)
			bes = append(bes, be.NewMeta())
		}
		err := e.UpsertService(uint16(fe.ID), fe.IP, fe.Port, bes, 0, false, svc.Type, true)
		c.Assert(err, IsNil)
	}
	e.checkService(testSvcs, c)

	// remove one backend
	testSvc1.Backends = []lb.Backend{*testBackend1}
	fe := &testSvc1.Frontend
	bes := []*lb.BackendMeta{}
	for _, be := range testSvc1.Backends {
		bes = append(bes, be.NewMeta())
	}
	err := e.UpsertService(uint16(fe.ID), fe.IP, fe.Port, bes, 0, false, testSvc1.Type, true)
	c.Assert(err, IsNil)
	e.checkService(testSvcs, c)

	// Should remove the service and the backend, but keep another service and its backends
	testSvcs = []*lb.SVC{testSvc2}
	err = e.DeleteService(testSvc1.Frontend, 0)
	c.Assert(err, IsNil)
	err = e.DeleteBackendByID(uint16(testSvc1.Backends[0].ID), false)
	c.Assert(err, IsNil)
	e.checkService(testSvcs, c)

	// Should delete both backends of service
	oldBackends := testSvc2.Backends
	testSvc2.Backends = []lb.Backend{}
	fe = &testSvc2.Frontend
	err = e.UpsertService(uint16(fe.ID), fe.IP, fe.Port, nil, 0, false, testSvc2.Type, true)
	c.Assert(err, IsNil)
	for _, b := range oldBackends {
		err = e.DeleteBackendByID(uint16(b.ID), false)
		c.Assert(err, IsNil)
	}
	e.checkService(testSvcs, c)

	// Should delete the remaining service
	testSvcs = []*lb.SVC{}
	err = e.DeleteService(testSvc2.Frontend, 0)
	c.Assert(err, IsNil)
	e.checkService(testSvcs, c)
}
