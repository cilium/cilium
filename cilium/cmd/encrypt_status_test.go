// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/hex"
	"net"
	"runtime"

	"github.com/cilium/cilium/pkg/testutils"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type EncryptStatusSuite struct {
	currentNetNS netns.NsHandle
}

var _ = Suite(&EncryptStatusSuite{})

func (s *EncryptStatusSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	var err error
	s.currentNetNS, err = netns.Get()
	c.Assert(err, IsNil)
}

func getXfrmState(src string, dst string, spi int, key string) *netlink.XfrmState {
	k, _ := hex.DecodeString(key)
	return &netlink.XfrmState{
		Src:   net.ParseIP(src),
		Dst:   net.ParseIP(dst),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   spi,
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    k,
			ICVLen: 64,
		},
	}
}

func (s *EncryptStatusSuite) TestCountUniqueIPsecKeys(c *C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ns, err := netns.New()
	c.Assert(err, IsNil)
	defer func() { c.Assert(ns.Close(), IsNil) }()
	defer func() { c.Assert(netns.Set(s.currentNetNS), IsNil) }()

	keys := countUniqueIPsecKeys()
	c.Assert(keys, Equals, 0)

	err = netlink.XfrmStateAdd(getXfrmState("10.0.0.1", "10.0.0.2", 2, "611d0c8049dd88600ec4f9eded7b1ed540ea607f"))
	c.Assert(err, IsNil)

	// adding different state with same key
	err = netlink.XfrmStateAdd(getXfrmState("10.0.0.2", "10.0.0.1", 1, "611d0c8049dd88600ec4f9eded7b1ed540ea607f"))
	c.Assert(err, IsNil)

	keys = countUniqueIPsecKeys()
	c.Assert(keys, Equals, 1)

	err = netlink.XfrmStateAdd(getXfrmState("10.0.0.1", "10.0.0.2", 1, "383fa49ea57848c9e85af88a187321f81da54bb6"))
	c.Assert(err, IsNil)

	keys = countUniqueIPsecKeys()
	c.Assert(keys, Equals, 2)
}

const procTestFixtures = "fixtures/proc"

func (s *EncryptStatusSuite) TestGetXfrmStats(c *C) {
	errCount, m := getXfrmStats(procTestFixtures)
	currentCount := 0
	testCases := []struct {
		name string
		want int
	}{
		{name: "XfrmInError", want: 2},
		{name: "XfrmInBufferError", want: 0},
		{name: "XfrmInHdrError", want: 0},
		{name: "XfrmInNoStates", want: 225479},
		{name: "XfrmInStateProtoError", want: 141222},
		{name: "XfrmInStateModeError", want: 0},
		{name: "XfrmInStateSeqError", want: 0},
		{name: "XfrmInStateExpired", want: 0},
		{name: "XfrmInStateMismatch", want: 0},
		{name: "XfrmInStateInvalid", want: 0},
		{name: "XfrmInTmplMismatch", want: 0},
		{name: "XfrmInNoPols", want: 203389},
		{name: "XfrmInPolBlock", want: 0},
		{name: "XfrmInPolError", want: 0},
		{name: "XfrmOutError", want: 0},
		{name: "XfrmOutBundleGenError", want: 0},
		{name: "XfrmOutBundleCheckError", want: 0},
		{name: "XfrmOutNoStates", want: 36162},
		{name: "XfrmOutStateProtoError", want: 1886},
		{name: "XfrmOutStateModeError", want: 0},
		{name: "XfrmOutStateSeqError", want: 0},
		{name: "XfrmOutStateExpired", want: 0},
		{name: "XfrmOutPolBlock", want: 0},
		{name: "XfrmOutPolDead", want: 0},
		{name: "XfrmOutPolError", want: 0},
		{name: "XfrmFwdHdrError", want: 0},
		{name: "XfrmOutStateInvalid", want: 0},
		{name: "XfrmAcquireError", want: 0},
	}
	for _, test := range testCases {
		got := m[test.name]
		c.Assert(test.want, Equals, got)
		currentCount += got
	}
	c.Assert(currentCount, Equals, errCount)
}
