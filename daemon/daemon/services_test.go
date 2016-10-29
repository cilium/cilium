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
	svc1 = types.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: types.L4Addr{Port: 0},
	}
	svc2 = types.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: types.L4Addr{Port: 1},
	}
	wantSvcL4ID = &types.L3n4AddrID{
		ID:       123,
		L3n4Addr: svc2,
	}
)

func (ds *DaemonSuite) TestServices(c *C) {
	var nilSvcL4ID *types.L3n4AddrID
	// Set up last free ID with zero
	id, err := ds.d.GetMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, common.FirstFreeServiceID)

	ffsIDu16 := types.ServiceID(uint16(common.FirstFreeServiceID))

	svcL4ID, err := ds.d.PutServiceL4(svc1)
	c.Assert(err, Equals, nil)
	c.Assert(svcL4ID.ID, Equals, ffsIDu16)

	svcL4ID, err = ds.d.PutServiceL4(svc1)
	c.Assert(err, Equals, nil)
	c.Assert(svcL4ID.ID, Equals, ffsIDu16)

	svcL4ID, err = ds.d.PutServiceL4(svc2)
	c.Assert(err, Equals, nil)
	c.Assert(svcL4ID.ID, Equals, ffsIDu16+1)

	gotSvcL4ID, err := ds.d.GetServiceL4ID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	wantSvcL4ID.ID = ffsIDu16
	wantSvcL4ID.L3n4Addr = svc1
	c.Assert(gotSvcL4ID, DeepEquals, wantSvcL4ID)

	err = ds.d.DeleteServiceL4IDByUUID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotSvcL4ID, err = ds.d.GetServiceL4ID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotSvcL4ID, Equals, nilSvcL4ID)

	gotSvcL4ID, err = ds.d.GetServiceL4ID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	wantSvcL4ID.ID = types.ServiceID(common.FirstFreeServiceID + 1)
	wantSvcL4ID.L3n4Addr = svc2
	c.Assert(gotSvcL4ID, DeepEquals, wantSvcL4ID)

	err = ds.d.DeleteServiceL4IDByUUID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = ds.d.kvClient.SetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID, common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = ds.d.DeleteServiceL4IDByUUID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotSvcL4ID, err = ds.d.GetServiceL4ID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotSvcL4ID, Equals, nilSvcL4ID)

	gotSvcL4ID, err = ds.d.PutServiceL4(svc2)
	c.Assert(err, Equals, nil)
	c.Assert(gotSvcL4ID.ID, Equals, types.ServiceID(common.FirstFreeServiceID+1))

	sha256sum, err := svc2.SHA256Sum()
	c.Assert(err, Equals, nil)

	gotSvcL4ID, err = ds.d.GetServiceL4IDBySHA256(sha256sum)
	c.Assert(err, Equals, nil)
	c.Assert(gotSvcL4ID, DeepEquals, wantSvcL4ID)

	err = ds.d.DeleteServiceL4IDBySHA256(sha256sum)
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteServiceL4IDByUUID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	err = ds.d.DeleteServiceL4IDByUUID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)

	gotSvcL4ID, err = ds.d.PutServiceL4(svc2)
	c.Assert(err, Equals, nil)
	c.Assert(gotSvcL4ID.ID, Equals, ffsIDu16)

	gotSvcL4ID, err = ds.d.PutServiceL4(svc1)
	c.Assert(err, Equals, nil)
	c.Assert(gotSvcL4ID.ID, Equals, types.ServiceID(common.FirstFreeServiceID+1))
}

func (ds *DaemonSuite) TestGetMaxServiceID(c *C) {
	lastID := uint32(common.MaxSetOfServiceID - 1)
	err := ds.d.kvClient.SetValue(common.LastFreeServiceIDKeyPath, lastID)
	c.Assert(err, Equals, nil)

	id, err := ds.d.GetMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfServiceID - 1))
}
