// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"errors"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/utime"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
type AuthMapTestSuite struct{}

var _ = Suite(&AuthMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *AuthMapTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedCheck(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *AuthMapTestSuite) TestAuthMap(c *C) {
	err := initMap(10, true)
	c.Assert(err, IsNil)
	defer authMap.Unpin()

	_, err = authMap.Lookup(identity.NumericIdentity(1), identity.NumericIdentity(2), 1, policy.AuthTypeNull)
	c.Assert(errors.Is(err, ebpf.ErrKeyNotExist), Equals, true)

	err = authMap.Update(identity.NumericIdentity(1), identity.NumericIdentity(2), 1, policy.AuthTypeNull, 10)
	c.Assert(err, IsNil)

	info, err := authMap.Lookup(identity.NumericIdentity(1), identity.NumericIdentity(2), 1, policy.AuthTypeNull)
	c.Assert(err, IsNil)
	c.Assert(info.Expiration, Equals, utime.UTime(10))

	err = authMap.Update(identity.NumericIdentity(1), identity.NumericIdentity(2), 1, policy.AuthTypeNull, 20)
	c.Assert(err, IsNil)

	info, err = authMap.Lookup(identity.NumericIdentity(1), identity.NumericIdentity(2), 1, policy.AuthTypeNull)
	c.Assert(err, IsNil)
	c.Assert(info.Expiration, Equals, utime.UTime(20))

	err = authMap.Delete(identity.NumericIdentity(1), identity.NumericIdentity(2), 1, policy.AuthTypeNull)
	c.Assert(err, IsNil)

	_, err = authMap.Lookup(identity.NumericIdentity(1), identity.NumericIdentity(2), 1, policy.AuthTypeNull)
	c.Assert(errors.Is(err, ebpf.ErrKeyNotExist), Equals, true)
}
