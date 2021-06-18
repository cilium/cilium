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

// +build !privileged_tests

package iptables

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/option"

	"github.com/blang/semver"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type iptablesTestSuite struct{}

var _ = check.Suite(&iptablesTestSuite{})

type expectation struct {
	args string
	out  []byte
	err  error
}

type mockIptables struct {
	c            *check.C
	prog         string
	expectations []expectation
	index        int
}

func (ipt *mockIptables) addExpectation(args string, out []byte, err error) {
	ipt.expectations = append(ipt.expectations, expectation{args: args, out: out, err: err})
}

func (ipt *mockIptables) getProg() string {
	return ipt.prog
}

func (ipt *mockIptables) getVersion() (semver.Version, error) {
	return semver.Version{}, nil
}

func (ipt *mockIptables) runProgCombinedOutput(args []string, quiet bool) (out []byte, err error) {
	a := strings.Join(args, " ")
	i := ipt.index
	ipt.index++

	if len(ipt.expectations) < ipt.index {
		ipt.c.Errorf("%d: Unexpected %s %s", i, ipt.prog, a)
		return nil, fmt.Errorf("Unexpected %s %s", ipt.prog, a)
	}
	if a != ipt.expectations[i].args {
		ipt.c.Errorf("%d: Unexpected %s (%q != %q)", i, ipt.prog, a, ipt.expectations[i].args)
		return nil, fmt.Errorf("Unexpected %s %s", ipt.prog, a)
	}
	out = ipt.expectations[i].out
	err = ipt.expectations[i].err

	return out, err
}

func (ipt *mockIptables) runProg(args []string, quiet bool) error {
	out, err := ipt.runProgCombinedOutput(args, quiet)
	if len(out) > 0 {
		ipt.c.Errorf("%d: Unexpected output for %s %s", ipt.index-1, ipt.prog, strings.Join(args, " "))
	}
	return err
}

func (ipt *mockIptables) checkExpectations() error {
	if ipt.index != len(ipt.expectations) {
		return fmt.Errorf("%d unmet expectations", len(ipt.expectations)-ipt.index)
	}

	// reset index for further testing
	ipt.index = 0

	return nil
}

var mockManager = &IptablesManager{
	haveIp6tables:        false,
	haveSocketMatch:      true,
	ipEarlyDemuxDisabled: false,
	waitArgs:             nil,
}

func init() {
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
}

func (s *iptablesTestSuite) TestRemoveCiliumRulesv4(c *check.C) {
	mockIp4tables := &mockIptables{c: c, prog: "iptables"}
	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -D PREROUTING -m comment --comment cilium-feeder: CILIUM_PRE_mangle -j CILIUM_PRE_mangle",
		}, {
			args: "-t mangle -D POSTROUTING -m comment --comment cilium-feeder: CILIUM_POST_mangle -j CILIUM_POST_mangle",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -m socket --transparent -m comment --comment cilium: any->pod redirect proxied traffic to host proxy -j MARK --set-xmark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff",
		},
	}

	mockManager.removeCiliumRules("mangle", mockIp4tables, ciliumPrefix)
	err := mockIp4tables.checkExpectations()
	c.Assert(err, check.IsNil)
}
