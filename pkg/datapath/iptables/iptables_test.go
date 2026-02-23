// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectation struct {
	args string
	out  []byte
	err  error
}

type mockIptables struct {
	t            *testing.T
	prog         string
	ipset        string
	expectations []expectation
	index        int
	mode         string
}

func (ipt *mockIptables) getProg() string {
	return ipt.prog
}

func (ipt *mockIptables) getIpset() string {
	return ipt.ipset
}

func (ipt *mockIptables) getMode() string {
	return ipt.mode
}

func (ipt *mockIptables) runProgOutput(args []string) (out string, err error) {
	a := strings.Join(args, " ")
	i := ipt.index
	ipt.index++

	if len(ipt.expectations) < ipt.index {
		ipt.t.Errorf("%d: Unexpected %s %s", i, ipt.prog, a)
		return "", fmt.Errorf("Unexpected %s %s", ipt.prog, a)
	}
	if a != ipt.expectations[i].args {
		ipt.t.Errorf("%d: Unexpected %s (%q != %q)", i, ipt.prog, a, ipt.expectations[i].args)
		return "", fmt.Errorf("Unexpected %s %s", ipt.prog, a)
	}
	out = string(ipt.expectations[i].out)
	err = ipt.expectations[i].err

	return out, err
}

func (ipt *mockIptables) runProg(args []string) error {
	out, err := ipt.runProgOutput(args)
	if len(out) > 0 {
		ipt.t.Errorf("%d: Unexpected output for %s %s", ipt.index-1, ipt.prog, strings.Join(args, " "))
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

var mockManager = &Manager{
	haveIp6tables:        false,
	haveSocketMatch:      true,
	haveBPFSocketAssign:  false,
	ipEarlyDemuxDisabled: false,
	sharedCfg: SharedConfig{
		EnableIPv4: true,
		EnableIPv6: true,
	},
}

func TestRenameCustomChain(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S CILIUM_PRE_mangle",
		},
		{
			args: "-t mangle -E CILIUM_PRE_mangle OLD_CILIUM_PRE_mangle",
		},
	}
	chain := &customChain{
		table: "mangle",
		name:  "CILIUM_PRE_mangle",
	}
	chain.doRename(mockIp4tables, "OLD_CILIUM_PRE_mangle")
	err := mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}
	mockIp6tables.expectations = mockIp4tables.expectations
	chain.doRename(mockIp6tables, "OLD_CILIUM_PRE_mangle")
	err = mockIp6tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCopyProxyRulesv4(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-random-proxy proxy" -j TPROXY --on-port 43499 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff",
		},
	}

	// Copies DNS proxy rules from OLD_CILIUM_PRE_mangle to CILIUM_PRE_mangle
	mockManager.doCopyProxyRules(mockIp4tables, "mangle", tproxyMatch, "cilium-dns-egress", "OLD_"+ciliumPreMangleChain, ciliumPreMangleChain)
	err := mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCopyProxyRulesv6(t *testing.T) {
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}
	mockIp6tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-random-proxy proxy" -j TPROXY --on-port 43499 --on-ip :: --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff",
		},
	}

	// Copies DNS proxy rules from OLD_CILIUM_PRE_mangle to CILIUM_PRE_mangle
	mockManager.doCopyProxyRules(mockIp6tables, "mangle", tproxyMatch, "cilium-dns-egress", "OLD_"+ciliumPreMangleChain, ciliumPreMangleChain)
	err := mockIp6tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddProxyRulesv4(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37379",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37379",
		},
	}

	// Adds new proxy rules
	mockManager.addProxyRules(mockIp4tables, "127.0.0.1", 37379, "cilium-dns-egress")
	err := mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
`),
		},
	}

	// Nothing to add
	mockManager.addProxyRules(mockIp4tables, "127.0.0.1", 37379, "cilium-dns-egress")
	err = mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0x4920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37380",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0x4920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37380",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff",
		},
	}

	// New port number, adds new ones, deletes stale rules. Does not touch OLD_ chains
	mockManager.addProxyRules(mockIp4tables, "127.0.0.1", 37380, "cilium-dns-egress")
	err = mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37379",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37379",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 37379 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 37379 --on-ip 0.0.0.0 --tproxy-mark 0x200/0xffffffff",
		},
	}

	// Same port number, new IP, adds new ones, deletes stale rules. Does not touch OLD_ chains
	mockManager.addProxyRules(mockIp4tables, "127.0.0.1", 37379, "cilium-dns-egress")
	err = mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0x3920200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 37379 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0x4920200 -m comment --comment cilium: TPROXY to host cilium-dns proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37380",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0x4920200 -m comment --comment cilium: TPROXY to host cilium-dns proxy -j TPROXY --tproxy-mark 0x200 --on-ip 127.0.0.1 --on-port 37380",
		},
	}

	// Adds new proxy rules for different service, whose name is a prefix of an existing one
	mockManager.addProxyRules(mockIp4tables, "127.0.0.1", 37380, "cilium-dns")
	err = mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetProxyPorts(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -n -L CILIUM_PRE_mangle",
			out: []byte(
				`Chain CILIUM_PRE_mangle (1 references)
target     prot opt source               destination
MARK       all  --  0.0.0.0/0            0.0.0.0/0            socket --transparent /* cilium: any->pod redirect proxied traffic to host proxy */ MARK set 0x200
TPROXY     tcp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd5a90200 /* cilium: TPROXY to host cilium-dns-egress proxy */ TPROXY redirect 127.0.0.1:43477 mark 0x200/0xffffffff
TPROXY     udp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd5a90200 /* cilium: TPROXY to host cilium-dns-egress proxy */ TPROXY redirect 127.0.0.1:43477 mark 0x200/0xffffffff
TPROXY     tcp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd7a90200 /* cilium: TPROXY to host cilium-dns-egress proxy */ TPROXY redirect 127.0.0.1:43479 mark 0x200/0xffffffff
TPROXY     udp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd7a90200 /* cilium: TPROXY to host cilium-dns-egress proxy */ TPROXY redirect 127.0.0.1:43479 mark 0x200/0xffffffff
`),
		},
	}

	// Finds the latest port number if multiple rules for the same proxy name
	portMap := mockManager.doGetProxyPorts(mockIp4tables)
	if len(portMap) != 1 || portMap["cilium-dns-egress"] != uint16(43479) {
		t.Fatalf("expected port number %d, got %d, portMap: %v", uint16(43479), portMap["cilium-dns-egress"], portMap)
	}
	if err := mockIp4tables.checkExpectations(); err != nil {
		t.Fatal(err)
	}

	// Now test the proxy port fetch when the proxy is not DNS. It should
	// fallback to 0.0.0.0 instead of localhost.
	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -n -L CILIUM_PRE_mangle",
			out: []byte(
				`Chain CILIUM_PRE_mangle (1 references)
target     prot opt source               destination
MARK       all  --  0.0.0.0/0            0.0.0.0/0            socket --transparent /* cilium: any->pod redirect proxied traffic to host proxy */ MARK set 0x200
TPROXY     tcp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd5a90200 /* cilium: TPROXY to host cilium-random-ingress proxy */ TPROXY redirect 0.0.0.0:43477 mark 0x200/0xffffffff
TPROXY     udp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd5a90200 /* cilium: TPROXY to host cilium-random-ingress proxy */ TPROXY redirect 0.0.0.0:43477 mark 0x200/0xffffffff
TPROXY     tcp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd7a90200 /* cilium: TPROXY to host cilium-random-ingress proxy */ TPROXY redirect 0.0.0.0:43479 mark 0x200/0xffffffff
TPROXY     udp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd7a90200 /* cilium: TPROXY to host cilium-random-ingress proxy */ TPROXY redirect 0.0.0.0:43479 mark 0x200/0xffffffff
`),
		},
	}

	portMap = mockManager.doGetProxyPorts(mockIp4tables)
	if len(portMap) != 1 || portMap["cilium-random-ingress"] != uint16(43479) {
		t.Fatalf("expected port number %d, got %d, portMap: %v", uint16(43479), portMap["cilium-random-ingress"], portMap)
	}
	if err := mockIp4tables.checkExpectations(); err != nil {
		t.Fatal(err)
	}
}

func TestAddProxyRulesv6(t *testing.T) {
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}
	mockIp6tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip ::1 --on-port 43477",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip ::1 --on-port 43477",
		},
	}

	// Adds new proxy rules
	mockManager.addProxyRules(mockIp6tables, "::1", 43477, "cilium-dns-egress")
	err := mockIp6tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp6tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
`),
		},
	}

	// Nothing to add
	mockManager.addProxyRules(mockIp6tables, "::1", 43477, "cilium-dns-egress")
	err = mockIp6tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp6tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd7a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip ::1 --on-port 43479",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0xd7a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --tproxy-mark 0x200 --on-ip ::1 --on-port 43479",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff",
		},
	}

	// New port number, adds new ones, deletes stale rules. Does not touch OLD_ chains
	mockManager.addProxyRules(mockIp6tables, "::1", 43479, "cilium-dns-egress")
	err = mockIp6tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}

	mockIp6tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd8a90200 -m comment --comment cilium: TPROXY to host cilium-dns proxy -j TPROXY --tproxy-mark 0x200 --on-ip ::1 --on-port 43480",
		}, {
			args: "-t mangle -A CILIUM_PRE_mangle -p udp -m mark --mark 0xd8a90200 -m comment --comment cilium: TPROXY to host cilium-dns proxy -j TPROXY --tproxy-mark 0x200 --on-ip ::1 --on-port 43480",
		},
	}

	// Adds new proxy rules for different service, whose name is a prefix of an existing one
	mockManager.addProxyRules(mockIp6tables, "::1", 43480, "cilium-dns")
	err = mockIp6tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRemoveCiliumRulesv4(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp4tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -D PREROUTING -m comment --comment cilium-feeder: CILIUM_PRE_mangle -j OLD_CILIUM_PRE_mangle",
		}, {
			args: "-t mangle -D POSTROUTING -m comment --comment cilium-feeder: CILIUM_POST_mangle -j OLD_CILIUM_POST_mangle",
		}, {
			args: "-t mangle -D OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment cilium: any->pod redirect proxied traffic to host proxy -j MARK --set-xmark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip 127.0.0.1 --tproxy-mark 0x200/0xffffffff",
		},
	}

	// Only removes Cilium chains with the OLD_ prefix
	mockManager.removeCiliumRules("mangle", mockIp4tables, oldCiliumPrefix+"CILIUM_")
	err := mockIp4tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRemoveCiliumRulesv6(t *testing.T) {
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}
	mockIp6tables.expectations = []expectation{
		{
			args: "-t mangle -S",
			out: []byte(
				`-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-N OLD_CILIUM_POST_mangle
-N OLD_CILIUM_PRE_mangle
-N CILIUM_POST_mangle
-N CILIUM_PRE_mangle
-N KUBE-KUBELET-CANARY
-N KUBE-PROXY-CANARY
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j OLD_CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j OLD_CILIUM_POST_mangle
-A PREROUTING -m comment --comment "cilium-feeder: CILIUM_PRE_mangle" -j CILIUM_PRE_mangle
-A POSTROUTING -m comment --comment "cilium-feeder: CILIUM_POST_mangle" -j CILIUM_POST_mangle
-A OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -m socket --transparent -m comment --comment "cilium: any->pod redirect proxied traffic to host proxy" -j MARK --set-xmark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
-A CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment "cilium: TPROXY to host cilium-dns-egress proxy" -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff
`),
		}, {
			args: "-t mangle -D PREROUTING -m comment --comment cilium-feeder: CILIUM_PRE_mangle -j OLD_CILIUM_PRE_mangle",
		}, {
			args: "-t mangle -D POSTROUTING -m comment --comment cilium-feeder: CILIUM_POST_mangle -j OLD_CILIUM_POST_mangle",
		}, {
			args: "-t mangle -D OLD_CILIUM_PRE_mangle -m socket --transparent -m comment --comment cilium: any->pod redirect proxied traffic to host proxy -j MARK --set-xmark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D OLD_CILIUM_PRE_mangle -p tcp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff",
		}, {
			args: "-t mangle -D OLD_CILIUM_PRE_mangle -p udp -m mark --mark 0xd5a90200 -m comment --comment cilium: TPROXY to host cilium-dns-egress proxy -j TPROXY --on-port 43477 --on-ip ::1 --tproxy-mark 0x200/0xffffffff",
		},
	}

	// Only removes Cilium chains with the OLD_ prefix
	mockManager.removeCiliumRules("mangle", mockIp6tables, oldCiliumPrefix+"CILIUM_")
	err := mockIp6tables.checkExpectations()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNodeIpsetNATCmds(t *testing.T) {
	allocRange := "10.0.0.0/16"
	ipset := "1.1.1.1"
	tests := []struct {
		masqueradeInterfaces []string
		expected             [][]string
	}{
		{
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat",
					"-s", "10.0.0.0/16",
					"-m", "set",
					"--match-set", "1.1.1.1", "dst",
					"-m", "comment",
					"--comment", "exclude traffic to cluster nodes from masquerade",
					"-j", "ACCEPT",
				},
			},
		},
		{
			masqueradeInterfaces: []string{"eth+"},
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat",
					"-o", "eth+",
					"-m", "set",
					"--match-set", "1.1.1.1", "dst",
					"-m", "comment",
					"--comment", "exclude traffic to cluster nodes from masquerade",
					"-j", "ACCEPT",
				},
			},
		},
		{
			masqueradeInterfaces: []string{"eth+", "ens+"},
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat",
					"-o", "eth+",
					"-m", "set",
					"--match-set", "1.1.1.1", "dst",
					"-m", "comment",
					"--comment", "exclude traffic to cluster nodes from masquerade",
					"-j", "ACCEPT",
				},
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat",
					"-o", "ens+",
					"-m", "set",
					"--match-set", "1.1.1.1", "dst",
					"-m", "comment",
					"--comment", "exclude traffic to cluster nodes from masquerade",
					"-j", "ACCEPT",
				},
			},
		},
	}

	for _, tt := range tests {
		actual := nodeIpsetNATCmds(allocRange, ipset, tt.masqueradeInterfaces)

		assert.Equal(t, tt.expected, actual)
	}
}

func TestAllEgressMasqueradeCmds(t *testing.T) {
	allocRange := "10.0.0.0/16"
	snatDstExclusionCIDR := "192.168.0.0/16"
	tests := []struct {
		masqueradeInterfaces []string
		iptablesRandomFull   bool
		expected             [][]string
	}{
		{
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat", "!",
					"-d", "192.168.0.0/16",
					"-s", "10.0.0.0/16", "!",
					"-o", "cilium_+",
					"-m", "comment",
					"--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE",
				},
			},
		},
		{
			iptablesRandomFull: true,
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat", "!",
					"-d", "192.168.0.0/16",
					"-s", "10.0.0.0/16", "!",
					"-o", "cilium_+",
					"-m", "comment",
					"--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE",
					"--random-fully",
				},
			},
		},
		{
			masqueradeInterfaces: []string{"eth+"},
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat", "!",
					"-d", "192.168.0.0/16",
					"-o", "eth+",
					"-m", "comment",
					"--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE",
				},
			},
		},
		{
			masqueradeInterfaces: []string{"eth+", "ens+"},
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat", "!",
					"-d", "192.168.0.0/16",
					"-o", "eth+",
					"-m", "comment",
					"--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE",
				},
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat", "!",
					"-d", "192.168.0.0/16",
					"-o", "ens+",
					"-m", "comment",
					"--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE",
				},
			},
		},
		{
			masqueradeInterfaces: []string{"eth+", "ens+"},
			iptablesRandomFull:   true,
			expected: [][]string{
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat", "!",
					"-d", "192.168.0.0/16",
					"-o", "eth+",
					"-m", "comment",
					"--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE",
					"--random-fully",
				},
				{
					"-t", "nat",
					"-A", "CILIUM_POST_nat", "!",
					"-d", "192.168.0.0/16",
					"-o", "ens+",
					"-m", "comment",
					"--comment", "cilium masquerade non-cluster",
					"-j", "MASQUERADE",
					"--random-fully",
				},
			},
		},
	}

	for _, tt := range tests {
		actual := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, tt.masqueradeInterfaces,
			tt.iptablesRandomFull)

		assert.Equal(t, tt.expected, actual)
	}
}

func testTunnelRulesTunnelingEnabled(t *testing.T, port uint16) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}

	mockManager := &Manager{
		sharedCfg: SharedConfig{
			EnableIPv4:       true,
			EnableIPv6:       true,
			TunnelingEnabled: true,
			TunnelPort:       port,
		},
		ip4tables: mockIp4tables,
		ip6tables: mockIp6tables,
	}

	expected := "%s -A %s -p udp --dport %d -m comment --comment %s"

	mockIp4tables.expectations = []expectation{
		{args: fmt.Sprintf(expected, "-t filter", "CILIUM_OUTPUT", port, "cilium: ACCEPT for tunnel traffic -j ACCEPT")},
		{args: fmt.Sprintf(expected, "-t raw", "CILIUM_PRE_raw", port, "cilium: NOTRACK for tunnel traffic -j CT --notrack")},
		{args: fmt.Sprintf(expected, "-t raw", "CILIUM_OUTPUT_raw", port, "cilium: NOTRACK for tunnel traffic -j CT --notrack")},
	}
	mockIp6tables.expectations = mockIp4tables.expectations

	require.NoError(t, mockManager.addCiliumTunnelRules())
	require.NoError(t, mockIp4tables.checkExpectations())
	require.NoError(t, mockIp6tables.checkExpectations())
}

func TestTunnelVxlankRulesTunnelingEnabled(t *testing.T) {
	testTunnelRulesTunnelingEnabled(t, 8472)
}

func TestTunnelGeneveRulesTunnelingEnabled(t *testing.T) {
	testTunnelRulesTunnelingEnabled(t, 6081)
}

func TestTunnelRulesTunnelingDisabled(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}
	mockManager := &Manager{
		sharedCfg: SharedConfig{
			EnableIPv4:       true,
			EnableIPv6:       true,
			TunnelingEnabled: false,
		},
		ip4tables: mockIp4tables,
		ip6tables: mockIp6tables,
	}

	// With tunneling disabled, we don't expect any `iptables` or `ip6tables`
	// rules to be added, so leave `mockIp6tables.expectations` empty.
	require.NoError(t, mockManager.addCiliumTunnelRules())
	require.NoError(t, mockIp4tables.checkExpectations())
	require.NoError(t, mockIp6tables.checkExpectations())
}

func TestNoTrackHostPorts(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}

	testMgr := &Manager{
		haveIp6tables:        false,
		haveSocketMatch:      true,
		haveBPFSocketAssign:  false,
		ipEarlyDemuxDisabled: false,
		sharedCfg: SharedConfig{
			EnableIPv4: true,
			EnableIPv6: true,
		},
		ip4tables: mockIp4tables,
		ip6tables: mockIp6tables,
	}

	testState := make(noTrackHostPortsByPod)

	var testPod, testPod2 podAndNameSpace

	t.Run("test adding notrack host port", func(t *testing.T) {
		testPod = podAndNameSpace{namespace: "testns", podName: "testpod1"}
		ports := []string{"443/tcp"}

		mockIp4tables.expectations = append(mockIp4tables.expectations, []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		mockIp6tables.expectations = append(mockIp6tables.expectations, []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod, ports))
		assert.Contains(t, testState, testPod)

		// add a second time does not error out or trigger iptables commands
		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod, ports))

		// add same port entry for another pod, make sure we dont see any new iptables commands
		testPod2 = podAndNameSpace{namespace: "testns", podName: "testpod2"}
		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod2, ports))

		assert.Contains(t, testState, testPod)
		assert.Contains(t, testState, testPod2)

		// add another port. we expect to see the new rules being added, and then the 2 previous rules being deleted
		mockIp4tables.expectations = append(mockIp4tables.expectations, []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p tcp --match multiport --dports 443,999 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443,999 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		mockIp6tables.expectations = append(mockIp6tables.expectations, []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p tcp --match multiport --dports 443,999 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443,999 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod2, []string{"999/tcp", "443/tcp"}))
		assert.NoError(t, mockIp4tables.checkExpectations())
		assert.NoError(t, mockIp6tables.checkExpectations())
	})

	t.Run("test changing the port", func(t *testing.T) {
		mockIp4tables.expectations = []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p tcp --match multiport --dports 443,999 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443,999 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -A CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}

		mockIp6tables.expectations = []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p tcp --match multiport --dports 443,999 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443,999 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -A CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}

		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod2, []string{"443/udp"}))
		assert.NoError(t, mockIp4tables.checkExpectations())
		assert.NoError(t, mockIp6tables.checkExpectations())
	})

	t.Run("test empty ports annotation", func(t *testing.T) {
		testPod3 := podAndNameSpace{namespace: "123", podName: "321"}
		mockIp4tables.expectations = []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p udp --match multiport --dports 443,8123 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p udp --match multiport --sports 443,8123 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}

		mockIp6tables.expectations = []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p udp --match multiport --dports 443,8123 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p udp --match multiport --sports 443,8123 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}

		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod3, []string{"8123/udp"}))

		mockIp4tables.expectations = append(mockIp4tables.expectations, []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p udp --match multiport --dports 443,8123 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p udp --match multiport --sports 443,8123 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		mockIp6tables.expectations = append(mockIp6tables.expectations, []expectation{
			{args: "-t raw -A CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -A CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},

			{args: "-t raw -D CILIUM_PRE_raw -p udp --match multiport --dports 443,8123 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p udp --match multiport --sports 443,8123 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		// empty port should trigger a delete-like behaviour
		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod3, strings.Split("", "/")))

		assert.NoError(t, mockIp4tables.checkExpectations())
		assert.NoError(t, mockIp6tables.checkExpectations())
	})

	t.Run("test deleting notrack host port", func(t *testing.T) {
		mockIp4tables.expectations = []expectation{
			{args: "-t raw -D CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}

		mockIp6tables.expectations = []expectation{
			{args: "-t raw -D CILIUM_PRE_raw -p udp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p udp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}

		assert.NoError(t, testMgr.removeNoTrackHostPorts(testState, testPod2))

		// now we update the previous one with an empty set. should cause rules to be deleted since this pod is the last reference for port 443
		mockIp4tables.expectations = append(mockIp4tables.expectations, []expectation{
			{args: "-t raw -D CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		mockIp6tables.expectations = append(mockIp6tables.expectations, []expectation{
			{args: "-t raw -D CILIUM_PRE_raw -p tcp --match multiport --dports 443 -m comment --comment cilium no-track-host-ports -j CT --notrack"},
			{args: "-t raw -D CILIUM_OUTPUT_raw -p tcp --match multiport --sports 443 -m comment --comment cilium no-track-host-ports return traffic -j CT --notrack"},
		}...)

		assert.NoError(t, testMgr.setNoTrackHostPorts(testState, testPod, nil))

		assert.NoError(t, mockIp4tables.checkExpectations())
		assert.NoError(t, mockIp6tables.checkExpectations())
		assert.Empty(t, testState)
	})
}

func TestEncryptionRules(t *testing.T) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}

	testMgr := &Manager{
		haveSocketMatch:      true,
		haveBPFSocketAssign:  false,
		ipEarlyDemuxDisabled: false,
		sharedCfg: SharedConfig{
			EnableIPv4:      true,
			EnableIPv6:      true,
			EnableWireguard: true,
		},
		ip4tables: mockIp4tables,
		ip6tables: mockIp6tables,
	}
	t.Run("test adding iptables rules for wireguard encryption", func(t *testing.T) {

		mockIp4tables.expectations = []expectation{
			{args: "-t filter -A CILIUM_INPUT -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_INPUT chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_INPUT -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_INPUT chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_OUTPUT -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_OUTPUT chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_OUTPUT -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_OUTPUT chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_POST_nat -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_POST_nat chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_POST_nat -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_POST_nat chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_OUTPUT_nat -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_OUTPUT_nat chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_OUTPUT_nat -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_OUTPUT_nat chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_PRE_nat -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_PRE_nat chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_PRE_nat -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_PRE_nat chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_FORWARD -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_FORWARD chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_FORWARD -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_FORWARD chain -j ACCEPT"},
		}

		mockIp6tables.expectations = []expectation{
			{args: "-t filter -A CILIUM_INPUT -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_INPUT chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_INPUT -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_INPUT chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_OUTPUT -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_OUTPUT chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_OUTPUT -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_OUTPUT chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_POST_nat -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_POST_nat chain -j ACCEPT"},
			{args: "-t nat -A CILIUM_POST_nat -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from nat CILIUM_POST_nat chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_FORWARD -m mark --mark 0x00000e00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_FORWARD chain -j ACCEPT"},
			{args: "-t filter -A CILIUM_FORWARD -m mark --mark 0x00000d00/0x00000f00 -m comment --comment exclude encrypt/decrypt marks from filter CILIUM_FORWARD chain -j ACCEPT"},
		}

		assert.NoError(t, testMgr.addCiliumAcceptEncryptionRules())
		assert.NoError(t, mockIp4tables.checkExpectations())
		assert.NoError(t, mockIp6tables.checkExpectations())

		mockIp4tables.expectations = []expectation{
			{args: "-t raw -I CILIUM_PRE_raw -m mark --mark 0x00000d00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
			{args: "-t raw -I CILIUM_PRE_raw -m mark --mark 0x00000e00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
			{args: "-t raw -I CILIUM_OUTPUT_raw -m mark --mark 0x00000d00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
			{args: "-t raw -I CILIUM_OUTPUT_raw -m mark --mark 0x00000e00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
		}

		mockIp6tables.expectations = []expectation{
			{args: "-t raw -I CILIUM_PRE_raw -m mark --mark 0x00000d00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
			{args: "-t raw -I CILIUM_PRE_raw -m mark --mark 0x00000e00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
			{args: "-t raw -I CILIUM_OUTPUT_raw -m mark --mark 0x00000d00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
			{args: "-t raw -I CILIUM_OUTPUT_raw -m mark --mark 0x00000e00/0x00000f00 -m comment --comment cilium-encryption-notrack: -j CT --notrack"},
		}

		assert.NoError(t, testMgr.addCiliumNoTrackEncryptionRules())
		assert.NoError(t, mockIp4tables.checkExpectations())
		assert.NoError(t, mockIp6tables.checkExpectations())
	})
}
