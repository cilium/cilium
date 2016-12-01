//
// Copyright 2016 Authors of Cilium
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
//
package server

import (
	"errors"
	"net"

	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
)

var (
	randomAddr1 = net.ParseIP("beef:beef:beef:beef:aaaa:aaaa:1111:0:1")
	randomAddr2 = net.ParseIP("beef:beef:beef:beef:aaaa:aaaa:1111:0:2")
	revNat1     = types.L3n4Addr{
		IP: randomAddr1,
		L4Addr: types.L4Addr{
			Protocol: types.TCP,
			Port:     1984,
		},
	}
	revNat2 = types.L3n4Addr{
		IP: randomAddr2,
		L4Addr: types.L4Addr{
			Protocol: types.TCP,
			Port:     1911,
		},
	}

	bes = []types.L3n4Addr{
		revNat1,
		revNat2,
	}
)

func (s *DaemonSuite) TestSVCAddIDOK(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)

	s.d.OnSVCAdd = func(fe types.L3n4AddrID, be []types.L3n4Addr, addRevNAT bool) error {
		c.Assert(fe, DeepEquals, *feWant)
		c.Assert(be, DeepEquals, bes)
		c.Assert(addRevNAT, Equals, false)
		return nil
	}

	err = s.c.SVCAdd(*feWant, bes, false)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestSVCAddIDFail(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)

	s.d.OnSVCAdd = func(fe types.L3n4AddrID, be []types.L3n4Addr, addRevNAT bool) error {
		c.Assert(fe, DeepEquals, *feWant)
		c.Assert(be, DeepEquals, bes)
		c.Assert(addRevNAT, Equals, true)
		return errors.New("Unable to read lbmap")
	}

	err = s.c.SVCAdd(*feWant, bes, true)
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
}

func (s *DaemonSuite) TestSVCDeleteOK(c *C) {
	feWant, err := types.NewL3n4Addr(types.TCP, randomAddr1, 1984)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	s.d.OnSVCDeleteBySHA256Sum = func(feL3n4SHA256Sum string) error {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return nil
	}

	err = s.c.SVCDelete(*feWant)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestSVCDeleteFail(c *C) {
	feWant, err := types.NewL3n4Addr(types.TCP, randomAddr1, 1984)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	s.d.OnSVCDeleteBySHA256Sum = func(feL3n4SHA256Sum string) error {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return errors.New("Unable to read lbmap")
	}

	err = s.c.SVCDelete(*feWant)
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
}

func (s *DaemonSuite) TestSVCDeleteBySHA256SumOK(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	s.d.OnSVCDeleteBySHA256Sum = func(feL3n4SHA256Sum string) error {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return nil
	}

	err = s.c.SVCDeleteBySHA256Sum(feL3n4SHA256Want)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestSVCDeleteBySHA256SumFail(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	s.d.OnSVCDeleteBySHA256Sum = func(feL3n4SHA256Sum string) error {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return errors.New("Unable to read lbmap")
	}

	err = s.c.SVCDeleteBySHA256Sum(feL3n4SHA256Want)
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
}

func (s *DaemonSuite) TestSVCDeleteAllOK(c *C) {
	s.d.OnSVCDeleteAll = func() error {
		return nil
	}

	err := s.c.SVCDeleteAll()
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestSVCDeleteAllFail(c *C) {
	s.d.OnSVCDeleteAll = func() error {
		return errors.New("Unable to read lbmap")
	}

	err := s.c.SVCDeleteAll()
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
}

func (s *DaemonSuite) TestSVCGetOK(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	lbSVCWant := types.LBSVC{
		FE:  *feWant,
		BES: bes,
	}

	s.d.OnSVCGetBySHA256Sum = func(feL3n4SHA256Sum string) (*types.LBSVC, error) {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return &lbSVCWant, nil
	}

	lbSvcReceived, err := s.c.SVCGet(feWant.L3n4Addr)
	c.Assert(err, IsNil)
	c.Assert(*lbSvcReceived, DeepEquals, lbSVCWant)
}

func (s *DaemonSuite) TestSVCGetFail(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	s.d.OnSVCGetBySHA256Sum = func(feL3n4SHA256Sum string) (*types.LBSVC, error) {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return nil, errors.New("Unable to read lbmap")
	}

	lbSvcReceived, err := s.c.SVCGet(feWant.L3n4Addr)
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
	c.Assert(lbSvcReceived, IsNil)
}

func (s *DaemonSuite) TestSVCGetBySHA256SumOK(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	lbSVCWant := types.LBSVC{
		FE:  *feWant,
		BES: bes,
	}

	s.d.OnSVCGetBySHA256Sum = func(feL3n4SHA256Sum string) (*types.LBSVC, error) {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return &lbSVCWant, nil
	}

	lbSvcReceived, err := s.c.SVCGetBySHA256Sum(feL3n4SHA256Want)
	c.Assert(err, IsNil)
	c.Assert(*lbSvcReceived, DeepEquals, lbSVCWant)
}

func (s *DaemonSuite) TestSVCGetBySHA256SumFail(c *C) {
	feWant, err := types.NewL3n4Addr(types.TCP, randomAddr1, 1984)
	c.Assert(err, IsNil)
	feL3n4SHA256Want, err := feWant.SHA256Sum()
	c.Assert(err, IsNil)

	s.d.OnSVCGetBySHA256Sum = func(feL3n4SHA256Sum string) (*types.LBSVC, error) {
		c.Assert(feL3n4SHA256Sum, Equals, feL3n4SHA256Want)
		return nil, errors.New("Unable to read lbmap")
	}

	lbSvcReceived, err := s.c.SVCGetBySHA256Sum(feL3n4SHA256Want)
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
	c.Assert(lbSvcReceived, IsNil)
}

func (s *DaemonSuite) TestSVCDumpOK(c *C) {
	feWant, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	wantLBSVC := []types.LBSVC{
		{
			FE:  *feWant,
			BES: bes,
		},
		{
			FE:  *feWant,
			BES: bes,
		},
	}
	s.d.OnSVCDump = func() ([]types.LBSVC, error) {
		return wantLBSVC, nil
	}

	lbSVCReceived, err := s.c.SVCDump()
	c.Assert(err, IsNil)
	c.Assert(wantLBSVC, DeepEquals, lbSVCReceived)
}

func (s *DaemonSuite) TestSVCDumpFail(c *C) {
	s.d.OnSVCDump = func() ([]types.LBSVC, error) {
		return nil, errors.New("Unable to read lbmap")
	}

	lbSVCReceived, err := s.c.SVCDump()
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
	c.Assert(lbSVCReceived, IsNil)
}

func (s *DaemonSuite) TestRevNATAddOK(c *C) {
	idWant := types.ServiceID(1)

	s.d.OnRevNATAdd = func(id types.ServiceID, revNAT types.L3n4Addr) error {
		c.Assert(id, DeepEquals, idWant)
		c.Assert(revNAT, DeepEquals, revNat1)
		return nil
	}

	err := s.c.RevNATAdd(idWant, revNat1)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestRevNATAddFail(c *C) {
	idWant := types.ServiceID(0)

	s.d.OnRevNATAdd = func(id types.ServiceID, revNAT types.L3n4Addr) error {
		c.Assert(id, DeepEquals, idWant)
		c.Assert(revNAT, DeepEquals, revNat1)
		return errors.New("ID 0 is reserved")
	}

	err := s.c.RevNATAdd(idWant, revNat1)
	c.Assert(err, ErrorMatches, ".*ID 0 is reserved.*")
}

func (s *DaemonSuite) TestRevNATDeleteOK(c *C) {
	idWant := types.ServiceID(1)

	s.d.OnRevNATDelete = func(id types.ServiceID) error {
		c.Assert(id, DeepEquals, idWant)
		return nil
	}

	err := s.c.RevNATDelete(idWant)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestRevNATDeleteFail(c *C) {
	idWant := types.ServiceID(0)

	s.d.OnRevNATDelete = func(id types.ServiceID) error {
		c.Assert(id, DeepEquals, idWant)
		return errors.New("ID 0 is reserved")
	}

	err := s.c.RevNATDelete(idWant)
	c.Assert(err, ErrorMatches, ".*ID 0 is reserved.*")
}

func (s *DaemonSuite) TestRevNATDeleteAllOK(c *C) {
	s.d.OnRevNATDeleteAll = func() error {
		return nil
	}

	err := s.c.RevNATDeleteAll()
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestRevNATDeleteAllFail(c *C) {
	s.d.OnRevNATDeleteAll = func() error {
		return errors.New("ID 0 is reserved")
	}

	err := s.c.RevNATDeleteAll()
	c.Assert(err, ErrorMatches, ".*ID 0 is reserved.*")
}

func (s *DaemonSuite) TestRevNATGetOK(c *C) {
	idWant := types.ServiceID(1)

	s.d.OnRevNATGet = func(id types.ServiceID) (*types.L3n4Addr, error) {
		c.Assert(id, DeepEquals, idWant)
		return &revNat1, nil
	}

	revNat1Received, err := s.c.RevNATGet(idWant)
	c.Assert(err, IsNil)
	c.Assert(*revNat1Received, DeepEquals, revNat1)
}

func (s *DaemonSuite) TestRevNATGetFail(c *C) {
	idWant := types.ServiceID(0)

	s.d.OnRevNATGet = func(id types.ServiceID) (*types.L3n4Addr, error) {
		c.Assert(id, DeepEquals, idWant)
		return nil, errors.New("ID 0 is reserved")
	}

	revNat1Received, err := s.c.RevNATGet(idWant)
	c.Assert(err, ErrorMatches, ".*ID 0 is reserved.*")
	c.Assert(revNat1Received, IsNil)
}

func (s *DaemonSuite) TestRevNATDumpOK(c *C) {
	wantRevNATs := []types.L3n4AddrID{
		{
			ID:       1984,
			L3n4Addr: revNat1,
		},
		{
			ID:       1911,
			L3n4Addr: revNat2,
		},
	}

	s.d.OnRevNATDump = func() ([]types.L3n4AddrID, error) {
		return wantRevNATs, nil
	}

	wantRevNATsReceived, err := s.c.RevNATDump()
	c.Assert(err, IsNil)
	c.Assert(wantRevNATsReceived, DeepEquals, wantRevNATs)
}

func (s *DaemonSuite) TestRevNATDumpFail(c *C) {
	s.d.OnRevNATDump = func() ([]types.L3n4AddrID, error) {
		return nil, errors.New("Unable to read lbmap")
	}

	lbSVCReceived, err := s.c.RevNATDump()
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
	c.Assert(lbSVCReceived, IsNil)
}

func (s *DaemonSuite) TestSyncLBMapOK(c *C) {
	s.d.OnSyncLBMap = func() error {
		return nil
	}

	err := s.c.SyncLBMap()
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestSyncLBMapFail(c *C) {
	s.d.OnSyncLBMap = func() error {
		return errors.New("Unable to read lbmap")
	}

	err := s.c.SyncLBMap()
	c.Assert(err, ErrorMatches, ".*Unable to read lbmap.*")
}
