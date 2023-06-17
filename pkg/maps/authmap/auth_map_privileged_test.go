// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"errors"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
type AuthMapTestSuite struct{}

var _ = Suite(&AuthMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *AuthMapTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *AuthMapTestSuite) TestAuthMap(c *C) {
	authMap := newMap(10)
	err := authMap.init()
	c.Assert(err, IsNil)
	defer authMap.bpfMap.Unpin()

	testKey := AuthKey{
		LocalIdentity:  1,
		RemoteIdentity: 2,
		RemoteNodeID:   1,
		AuthType:       1, // policy.AuthTypeNull
	}

	_, err = authMap.Lookup(testKey)
	c.Assert(errors.Is(err, ebpf.ErrKeyNotExist), Equals, true)

	err = authMap.Update(testKey, 10)
	c.Assert(err, IsNil)

	info, err := authMap.Lookup(testKey)
	c.Assert(err, IsNil)
	c.Assert(info.Expiration, Equals, utime.UTime(10))

	err = authMap.Update(testKey, 20)
	c.Assert(err, IsNil)

	info, err = authMap.Lookup(testKey)
	c.Assert(err, IsNil)
	c.Assert(info.Expiration, Equals, utime.UTime(20))

	err = authMap.Delete(testKey)
	c.Assert(err, IsNil)

	_, err = authMap.Lookup(testKey)
	c.Assert(errors.Is(err, ebpf.ErrKeyNotExist), Equals, true)
}
