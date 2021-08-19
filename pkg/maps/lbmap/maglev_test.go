// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build privileged_tests
// +build privileged_tests

package lbmap

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"

	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type MaglevSuite struct {
	prevMaglevTableSize int
	oldLim              unix.Rlimit
}

var _ = Suite(&MaglevSuite{})

func (s *MaglevSuite) SetUpSuite(c *C) {
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

	tmpLim := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	err = unix.Getrlimit(unix.RLIMIT_MEMLOCK, &s.oldLim)
	c.Assert(err, IsNil)
	// Otherwise opening the map might fail with EPERM
	err = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &tmpLim)
	c.Assert(err, IsNil)

	Init(InitParams{
		IPv4: option.Config.EnableIPv4,
		IPv6: option.Config.EnableIPv6,

		MaxSockRevNatMapEntries: option.Config.SockRevNatEntries,
		MaxEntries:              option.Config.LBMapEntries,
	})
}

func (s *MaglevSuite) TeadDownTest(c *C) {
	option.Config.MaglevTableSize = s.prevMaglevTableSize
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &s.oldLim)
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
	lbm := New(true, option.Config.MaglevTableSize)
	params := &UpsertServiceParams{
		ID:        1,
		IP:        net.ParseIP("1.1.1.1"),
		Port:      8080,
		Backends:  map[string]uint16{"backend-1": 1},
		Type:      loadbalancer.SVCTypeNodePort,
		UseMaglev: true,
	}
	err = lbm.UpsertService(params)
	c.Assert(err, IsNil)
	deleted, err = deleteMapIfMNotMatch(MaglevOuter4MapName, uint32(option.Config.MaglevTableSize))
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, false)
}
