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
package daemon

import (
	"net"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
)

var (
	l3n4Addr1 = types.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: types.L4Addr{Port: 0},
	}
	l3n4Addr2 = types.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: types.L4Addr{Port: 1},
	}
	wantL3n4AddrID = &types.L3n4AddrID{
		ID:       123,
		L3n4Addr: l3n4Addr2,
	}
)

func (ds *DaemonSuite) TestServices(c *C) {
	var nilL3n4AddrID *types.L3n4AddrID
	// Set up last free ID with zero
	id, err := ds.d.GetMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, common.FirstFreeServiceID)

	ffsIDu16 := types.ServiceID(uint16(common.FirstFreeServiceID))

	l3n4AddrID, err := ds.d.PutL3n4Addr(l3n4Addr1)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, ffsIDu16)

	l3n4AddrID, err = ds.d.PutL3n4Addr(l3n4Addr1)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, ffsIDu16)

	l3n4AddrID, err = ds.d.PutL3n4Addr(l3n4Addr2)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, ffsIDu16+1)

	gotL3n4AddrID, err := ds.d.GetL3n4AddrID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	wantL3n4AddrID.ID = ffsIDu16
	wantL3n4AddrID.L3n4Addr = l3n4Addr1
	c.Assert(gotL3n4AddrID, DeepEquals, wantL3n4AddrID)

	err = ds.d.DeleteL3n4AddrIDByUUID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotL3n4AddrID, err = ds.d.GetL3n4AddrID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID, Equals, nilL3n4AddrID)

	gotL3n4AddrID, err = ds.d.GetL3n4AddrID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	wantL3n4AddrID.ID = types.ServiceID(common.FirstFreeServiceID + 1)
	wantL3n4AddrID.L3n4Addr = l3n4Addr2
	c.Assert(gotL3n4AddrID, DeepEquals, wantL3n4AddrID)

	err = ds.d.DeleteL3n4AddrIDByUUID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = ds.d.kvClient.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = ds.d.DeleteL3n4AddrIDByUUID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotL3n4AddrID, err = ds.d.GetL3n4AddrID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID, Equals, nilL3n4AddrID)

	gotL3n4AddrID, err = ds.d.PutL3n4Addr(l3n4Addr2)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, types.ServiceID(common.FirstFreeServiceID+1))

	sha256sum, err := l3n4Addr2.SHA256Sum()
	c.Assert(err, Equals, nil)

	gotL3n4AddrID, err = ds.d.GetL3n4AddrIDBySHA256(sha256sum)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID, DeepEquals, wantL3n4AddrID)

	err = ds.d.DeleteL3n4AddrIDBySHA256(sha256sum)
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteL3n4AddrIDByUUID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteL3n4AddrIDByUUID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)

	gotL3n4AddrID, err = ds.d.PutL3n4Addr(l3n4Addr2)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, ffsIDu16)

	gotL3n4AddrID, err = ds.d.PutL3n4Addr(l3n4Addr1)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, types.ServiceID(common.FirstFreeServiceID+1))
}

func (ds *DaemonSuite) TestGetMaxServiceID(c *C) {
	lastID := uint32(common.MaxSetOfServiceID - 1)
	err := ds.d.kvClient.SetValue(common.LastFreeServiceIDKeyPath, lastID)
	c.Assert(err, Equals, nil)

	id, err := ds.d.GetMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfServiceID - 1))
}
