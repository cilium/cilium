// Copyright 2021 Authors of Cilium
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

package cmd

import (
	"encoding/hex"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	. "gopkg.in/check.v1"
	"net"
	"runtime"
	"testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type EncryptStatusSuite struct{}

var _ = Suite(&EncryptStatusSuite{})

const (
	procTestFixtures = "fixtures/proc"
)

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
	ns, err := netns.New()
	c.Assert(err, IsNil)

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

	ns.Close()
	runtime.UnlockOSThread()
}

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
