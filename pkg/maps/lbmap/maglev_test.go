// Copyright 2020 Authors of Cilium
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
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
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

func (s *MaglevSuite) TestSplitBackends(c *C) {
	const size = MaglevInnerElems
	tests := []struct {
		name     string
		backends []uint16
		expected [][size]uint16
	}{
		{
			name:     "empty",
			backends: []uint16{},
			expected: [][size]uint16{},
		},
		{
			name:     "nil",
			backends: nil,
			expected: nil,
		},
		{
			name:     "simple",
			backends: []uint16{8, 8, 8, 8},
			expected: [][size]uint16{
				{8, 8, 8, 8},
			},
		},
		{
			name:     "simple2",
			backends: []uint16{8, 8, 8, 8, 9},
			expected: [][size]uint16{
				{8, 8, 8, 8},
				{9, 0, 0, 0},
			},
		},
		{
			name:     "simple3",
			backends: []uint16{8, 8, 8, 8, 9, 10, 11},
			expected: [][size]uint16{
				{8, 8, 8, 8},
				{9, 10, 11, 0},
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		c.Assert(splitBackends(tt.backends), checker.DeepEquals, tt.expected)
	}
}

func (s *MaglevSuite) Benchmark_updateMaglevInnerMapWithoutMmap(c *C) {
	large := maglev.SupportedPrimes[len(maglev.SupportedPrimes)-1]
	InitMaglevMaps(true, true, uint32(large))

	innerMap, err := newMaglevInnerMap(MaglevInner4MapName, uint32(large), false)
	if err != nil {
		c.Assert(err, IsNil)
	}
	defer innerMap.Close()
	c.ResetTimer()
	c.StartTimer()
	for i := 0; i < c.N; i++ {
		updateMaglevInnerMap(innerMap, make([]uint16, 1024))
	}
	c.StopTimer()
}

func (s *MaglevSuite) Benchmark_updateMaglevInnerMapWithMmap(c *C) {
	large := maglev.SupportedPrimes[len(maglev.SupportedPrimes)-1]
	InitMaglevMaps(true, true, uint32(large))

	innerMap, err := newMaglevInnerMap(MaglevInner4MapName, uint32(large), true)
	if err != nil {
		c.Assert(err, IsNil)
	}
	defer innerMap.Close()
	c.ResetTimer()
	c.StartTimer()
	for i := 0; i < c.N; i++ {
		updateMaglevInnerMap(innerMap, make([]uint16, 1024))
	}
	c.StopTimer()
}
