// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"net"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/cilium/ebpf/rlimit"

	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func Test(t *testing.T) {
	TestingT(t)
}

type MaglevSuite struct {
	prevMaglevTableSize int
	prevNodePortAlg     string
}

var _ = Suite(&MaglevSuite{})

func (s *MaglevSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	vsn, err := version.GetKernelVersion()
	c.Assert(err, IsNil)
	constraint, err := versioncheck.Compile(">=4.11.0")
	c.Assert(err, IsNil)

	if !constraint(vsn) {
		// Currently, we run privileged tests on the 4.9 kernel in CI. That
		// kernel does not have the support for map-in-map. Thus, this skip.
		c.Skip("Skipping as >= 4.11 kernel is required for map-in-map support")
	}

	s.prevMaglevTableSize = option.Config.MaglevTableSize
	s.prevNodePortAlg = option.Config.NodePortAlg

	// Otherwise opening the map might fail with EPERM
	err = rlimit.RemoveMemlock()
	c.Assert(err, IsNil)

	option.Config.LBMapEntries = DefaultMaxEntries
	option.Config.NodePortAlg = option.NodePortAlgMaglev

	Init(InitParams{
		IPv4: option.Config.EnableIPv4,
		IPv6: option.Config.EnableIPv6,

		ServiceMapMaxEntries: option.Config.LBMapEntries,
		RevNatMapMaxEntries:  option.Config.LBMapEntries,
		MaglevMapMaxEntries:  option.Config.LBMapEntries,
	})
}

func (s *MaglevSuite) TeadDownTest(c *C) {
	option.Config.MaglevTableSize = s.prevMaglevTableSize
	option.Config.NodePortAlg = s.prevNodePortAlg
}

func (s *MaglevSuite) TestInitMaps(c *C) {
	option.Config.MaglevTableSize = 251
	err := InitMaglevMaps(true, false, uint32(option.Config.MaglevTableSize))
	c.Assert(err, IsNil)

	option.Config.MaglevTableSize = 509
	// M mismatch, so the map should be removed
	deleted, err := deleteMapIfMNotMatch(MaglevOuter4MapName, uint32(option.Config.MaglevTableSize))
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, true)

	// M is the same, but no entries, so the map should be removed too
	err = InitMaglevMaps(true, false, uint32(option.Config.MaglevTableSize))
	c.Assert(err, IsNil)
	deleted, err = deleteMapIfMNotMatch(MaglevOuter4MapName, uint32(option.Config.MaglevTableSize))
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, true)

	// Now insert the entry, so that the map should not be removed
	err = InitMaglevMaps(true, false, uint32(option.Config.MaglevTableSize))
	c.Assert(err, IsNil)
	lbm := New()
	params := &datapathTypes.UpsertServiceParams{
		ID:   1,
		IP:   net.ParseIP("1.1.1.1"),
		Port: 8080,
		ActiveBackends: map[string]*loadbalancer.Backend{"backend-1": {
			ID:     1,
			Weight: 1,
		}},
		Type:      loadbalancer.SVCTypeNodePort,
		UseMaglev: true,
	}
	err = lbm.UpsertService(params)
	c.Assert(err, IsNil)
	deleted, err = deleteMapIfMNotMatch(MaglevOuter4MapName, uint32(option.Config.MaglevTableSize))
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, false)
}
