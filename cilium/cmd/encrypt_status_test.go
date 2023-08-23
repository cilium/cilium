// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build privileged_tests

package cmd

import (
	"encoding/hex"
	"net"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type EncryptStatusSuite struct {
	currentNetNS netns.NsHandle
}

var _ = Suite(&EncryptStatusSuite{})

func (s *EncryptStatusSuite) SetUpSuite(c *C) {
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

func (s *EncryptStatusSuite) TestExtractMaxSequenceNumber(c *C) {
	ipOutput := `src 10.84.1.32 dst 10.84.0.30
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0x3cb23e00/0xffffff00 output-mark 0xe00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0xc3, bitmap 0x00000000
	sel src 0.0.0.0/0 dst 0.0.0.0/0
src 0.0.0.0 dst 10.84.1.32
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0xd00/0xf00 output-mark 0xd00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0x1410, bitmap 0x00000000
	sel src 0.0.0.0/0 dst 0.0.0.0/0
src 10.84.1.32 dst 10.84.2.145
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0x7e63e00/0xffffff00 output-mark 0xe00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0x13e0, bitmap 0x00000000
	sel src 0.0.0.0/0 dst 0.0.0.0/0`

	maxSeqNumber := extractMaxSequenceNumber(ipOutput)
	c.Assert(maxSeqNumber, Equals, int64(0x1410))
}

// Attempt to simulate a case where the output would be interrupted mid-sentence.
func (s *EncryptStatusSuite) TestExtractMaxSequenceNumberError(c *C) {
	ipOutput := `src 10.84.1.32 dst 10.84.0.30
	proto esp spi 0x00000003 reqid 1 mode tunnel
	replay-window 0
	mark 0x3cb23e00/0xffffff00 output-mark 0xe00/0xf00
	aead rfc4106(gcm(aes)) 0x64ad37a9d8a8f20fb2e74ef6000f9d580898719f 128
	anti-replay context: seq 0x0, oseq 0x`

	maxSeqNumber := extractMaxSequenceNumber(ipOutput)
	c.Assert(maxSeqNumber, Equals, int64(0))
}
