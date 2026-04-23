// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
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

var mockManager = &manager{
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
			tt.iptablesRandomFull, nil, 0)

		assert.Equal(t, tt.expected, actual)
	}
}

// TestAllEgressMasqueradeCmdsNATExcludedPorts verifies that excluded ports are
// bracketed with statistic-based --to-ports ranges so the kernel never picks
// them as an SNAT source port.
func TestAllEgressMasqueradeCmdsNATExcludedPorts(t *testing.T) {
	allocRange := "10.0.0.0/16"
	snatDstExclusionCIDR := "192.168.0.0/16"

	t.Run("no excluded ports — single plain MASQUERADE rule", func(t *testing.T) {
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, nil, 0)
		require.Len(t, cmds, 1)
		require.NotContains(t, cmds[0], "--to-ports")
		require.NotContains(t, cmds[0], "-p")
		require.Contains(t, cmds[0], "MASQUERADE")
	})

	t.Run("single excluded port — tcp+udp split rules plus catch-all", func(t *testing.T) {
		// Exclude WireGuard port 51871 (above natMinSNATPort=32768).
		// Segments: [32768-51870], [51872-65535] → 2 segs × 2 protos + 1 catch-all = 5 rules.
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, []uint16{51871}, 32768)
		require.Len(t, cmds, 5)

		// tcp lower (statistic), tcp upper, udp lower (statistic), udp upper, catch-all
		require.Contains(t, cmds[0], "-p")
		require.Contains(t, cmds[0], "tcp")
		require.Contains(t, cmds[0], "--every")
		require.Contains(t, cmds[0], "32768-51870")

		require.Contains(t, cmds[1], "-p")
		require.Contains(t, cmds[1], "tcp")
		require.NotContains(t, cmds[1], "--every")
		require.Contains(t, cmds[1], "51872-65535")

		require.Contains(t, cmds[2], "-p")
		require.Contains(t, cmds[2], "udp")
		require.Contains(t, cmds[2], "--every")
		require.Contains(t, cmds[2], "32768-51870")

		require.Contains(t, cmds[3], "-p")
		require.Contains(t, cmds[3], "udp")
		require.NotContains(t, cmds[3], "--every")
		require.Contains(t, cmds[3], "51872-65535")

		// Catch-all: no protocol, no --to-ports.
		require.NotContains(t, cmds[4], "-p")
		require.NotContains(t, cmds[4], "--to-ports")
	})

	t.Run("two excluded ports — three segments per protocol", func(t *testing.T) {
		// Ports 40000 and 51871 both above natMinSNATPort=32768.
		// 3 segs × 2 protos + 1 catch-all = 7 rules.
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, []uint16{40000, 51871}, 32768)
		require.Len(t, cmds, 7)
		// Last rule is the catch-all.
		require.NotContains(t, cmds[6], "--to-ports")
	})

	t.Run("excluded port at boundary 65535 — only lower segment", func(t *testing.T) {
		// 1 seg [32768-65534] × 2 protos + 1 catch-all = 3 rules; no statistic needed.
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, []uint16{65535}, 32768)
		require.Len(t, cmds, 3)
		require.Contains(t, cmds[0], "32768-65534")
		require.NotContains(t, cmds[0], "--every")
	})

	t.Run("excluded port below natMinSNATPort — falls back to plain MASQUERADE", func(t *testing.T) {
		// Port 8472 < natMinSNATPort=32768 → no effective excluded ports in NAT range.
		// Falls back to plain MASQUERADE (backwards compatible).
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, []uint16{8472}, 32768)
		require.Len(t, cmds, 1)
		require.NotContains(t, cmds[0], "--to-ports")
	})

	t.Run("excluded port with --random-fully", func(t *testing.T) {
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, true, []uint16{51871}, 32768)
		// 2 segs × 2 protos + 1 catch-all = 5 rules
		require.Len(t, cmds, 5)
		for _, cmd := range cmds {
			require.Contains(t, cmd, "--random-fully")
		}
	})

	t.Run("excluded port with masquerade interface — one rule set per iface", func(t *testing.T) {
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, []string{"eth0", "ens5"}, false, []uint16{51871}, 32768)
		// 2 interfaces × 5 rules each = 10 rules
		require.Len(t, cmds, 10)
	})
}

// TestAllEgressMasqueradeCmdsRealWorldConfigs verifies the masquerade rule
// structure produced by allEgressMasqueradeCmds under four real-world Cilium
// configurations that each affect which ports must be excluded from SNAT source
// port selection:
//
//   - NodePort enabled only           → no excluded ports; natMinSNATPort = 32768
//   - VXLAN tunneling only            → exclude 8472; natMinSNATPort = 0
//   - Geneve tunneling only           → exclude 6081; natMinSNATPort = 0
//   - VXLAN tunneling + NodePort      → exclude 8472; natMinSNATPort = 32768
//
// For each configuration the test checks:
//  1. The correct number of iptables rules is generated.
//  2. Every excluded port is absent from all --to-ports ranges.
//  3. Port ranges are contiguous across segments (no port is double-covered or
//     left out).
//  4. The catch-all (no --to-ports, no -p) is always the last rule.
func TestAllEgressMasqueradeCmdsRealWorldConfigs(t *testing.T) {
	const (
		vxlanPort  uint16 = 8472
		genevePort uint16 = 6081
		// NodePortMax default is 32767; SNAT starts at NodePortMax+1.
		natMinNodePort uint16 = 32768
	)

	allocRange := "10.0.0.0/16"
	snatDstExclusionCIDR := "192.168.0.0/16"

	// portRangesFromCmds collects all "--to-ports X-Y" values from a rule set.
	portRangesFromCmds := func(cmds [][]string) []string {
		var ranges []string
		for _, cmd := range cmds {
			for i, tok := range cmd {
				if tok == "--to-ports" && i+1 < len(cmd) {
					ranges = append(ranges, cmd[i+1])
				}
			}
		}
		return ranges
	}

	// portCoveredByRange returns true when port p falls inside "lo-hi".
	portCoveredByRange := func(t *testing.T, portRange string, p uint16) bool {
		t.Helper()
		var lo, hi uint16
		_, err := fmt.Sscanf(portRange, "%d-%d", &lo, &hi)
		require.NoError(t, err, "malformed port range %q", portRange)
		return p >= lo && p <= hi
	}

	// assertExcludedPortAbsent verifies that none of the emitted --to-ports
	// ranges include the excluded port.
	assertExcludedPortAbsent := func(t *testing.T, cmds [][]string, port uint16) {
		t.Helper()
		for _, r := range portRangesFromCmds(cmds) {
			require.False(t, portCoveredByRange(t, r, port),
				"excluded port %d should not be covered by range %s", port, r)
		}
	}

	// assertCatchAllIsLast verifies the last rule has no -p and no --to-ports.
	assertCatchAllIsLast := func(t *testing.T, cmds [][]string) {
		t.Helper()
		last := cmds[len(cmds)-1]
		require.NotContains(t, last, "-p", "catch-all must not have -p")
		require.NotContains(t, last, "--to-ports", "catch-all must not have --to-ports")
		require.Contains(t, last, "MASQUERADE", "catch-all must jump to MASQUERADE")
	}

	// assertSegmentsCoverRange verifies that the union of all --to-ports ranges
	// for a given protocol exactly covers [minPort, 65535] \ {excludedPorts...}
	// without gaps or overlaps.
	assertSegmentsCoverRange := func(t *testing.T, cmds [][]string, proto string, minPort uint16, excludedPorts ...uint16) {
		t.Helper()
		excluded := make(map[uint16]bool)

		for _, p := range excludedPorts {
			excluded[p] = true
		}

		// Gather ranges for this protocol.
		var protoRanges [][2]uint16
		for _, cmd := range cmds {
			isProto := false

			for i, tok := range cmd {
				if tok == "-p" && i+1 < len(cmd) && cmd[i+1] == proto {
					isProto = true
				}
			}

			if !isProto {
				continue
			}

			for i, tok := range cmd {
				if tok == "--to-ports" && i+1 < len(cmd) {
					var lo, hi uint16
					_, err := fmt.Sscanf(cmd[i+1], "%d-%d", &lo, &hi)
					require.NoError(t, err)
					protoRanges = append(protoRanges, [2]uint16{lo, hi})
				}
			}
		}

		// Walk from minPort to 65535 and verify every non-excluded port is
		// covered by exactly one range.
		for p := uint32(minPort); p <= 65535; p++ {
			if excluded[uint16(p)] {
				continue
			}

			covered := 0
			for _, r := range protoRanges {
				if uint16(p) >= r[0] && uint16(p) <= r[1] {
					covered++
				}
			}

			require.Equal(t, 1, covered,
				"proto %s: port %d covered by %d ranges (want 1)", proto, p, covered)
			if covered != 1 {
				// Don't spam failures for every port in a bad range.
				break
			}
		}
	}

	t.Run("nodeport enabled only — no excluded ports, full range from 32768", func(t *testing.T) {
		// NodePort enabled but no tunneling/WG → no Cilium-owned kernel sockets.
		// With no effective excluded ports, falls back to plain MASQUERADE (1 rule).
		// natMinSNATPort=32768 is irrelevant when there are no excluded ports.
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, nil, natMinNodePort)
		require.Len(t, cmds, 1, "expected single plain MASQUERADE rule")
		require.NotContains(t, cmds[0], "--to-ports")
		require.NotContains(t, cmds[0], "-p")
		require.Contains(t, cmds[0], "MASQUERADE")
	})

	t.Run("VXLAN tunneling only — exclude 8472, no nodeport range constraint", func(t *testing.T) {
		// No NodePort → natMinSNATPort=0 (or 1); excluded port 8472 in range.
		// 2 segments × 2 protos + 1 catch-all = 5 rules.
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, []uint16{vxlanPort}, 0)
		require.Len(t, cmds, 5, "expected 2 segs × 2 protos + catch-all")

		assertExcludedPortAbsent(t, cmds, vxlanPort)
		assertCatchAllIsLast(t, cmds)

		// TCP and UDP each cover [0, 8471] ∪ [8473, 65535].
		assertSegmentsCoverRange(t, cmds, "tcp", 0, vxlanPort)
		assertSegmentsCoverRange(t, cmds, "udp", 0, vxlanPort)
	})

	t.Run("Geneve tunneling only — exclude 6081, no nodeport range constraint", func(t *testing.T) {
		// Same structure as VXLAN but with port 6081.
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, []uint16{genevePort}, 0)
		require.Len(t, cmds, 5, "expected 2 segs × 2 protos + catch-all")

		assertExcludedPortAbsent(t, cmds, genevePort)
		assertCatchAllIsLast(t, cmds)

		assertSegmentsCoverRange(t, cmds, "tcp", 0, genevePort)
		assertSegmentsCoverRange(t, cmds, "udp", 0, genevePort)
	})

	t.Run("VXLAN tunneling + NodePort — exclude 8472, range starts at 32768", func(t *testing.T) {
		// NodePort max=32767 → natMinSNATPort=32768; VXLAN port 8472 < 32768 → skipped.
		// No effective excluded ports in [32768,65535] → plain MASQUERADE (backwards compat).
		//
		// Note: BPF SNAT already enforces the [32768,65535] range on the fast path;
		// the iptables rule catches the non-BPF path and must not clobber ports that
		// BPF manages. Since 8472 < 32768, it's already outside the SNAT range —
		// no split needed.
		cmds := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, []uint16{vxlanPort}, natMinNodePort)
		require.Len(t, cmds, 1, "VXLAN port is below natMinSNATPort; expect plain MASQUERADE")
		require.NotContains(t, cmds[0], "--to-ports")
		require.NotContains(t, cmds[0], "-p")

		// Double-check the excluded port is not in any range (trivially true, but explicit).
		assertExcludedPortAbsent(t, cmds, vxlanPort)
	})
}

func testTunnelRulesTunnelingEnabled(t *testing.T, port uint16) {
	mockIp4tables := &mockIptables{t: t, prog: "iptables"}
	mockIp6tables := &mockIptables{t: t, prog: "ip6tables"}

	mockManager := &manager{
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
	mockManager := &manager{
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

	testMgr := &manager{
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

	testMgr := &manager{
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

// TestAddNoTrackPodTrafficRules verifies that when InstallNoConntrackIptRules
// is enabled, addNoTrackPodTrafficRules generates the correct iptables rules
// to skip conntrack for pod traffic in both CILIUM_PRE_raw and
// CILIUM_OUTPUT_raw chains. This covers the "Skip conntrack for pod traffic"
// scenario previously tested by K8sDatapathConfig.
func TestAddNoTrackPodTrafficRules(t *testing.T) {
	podsCIDR := "10.0.0.0/16"

	mockIp4 := &mockIptables{
		t:    t,
		prog: "iptables",
		expectations: []expectation{
			// CILIUM_PRE_raw -s podsCIDR
			{args: "-t raw -I CILIUM_PRE_raw -s 10.0.0.0/16 -m comment --comment cilium: NOTRACK for pod traffic -j CT --notrack"},
			// CILIUM_PRE_raw -d podsCIDR
			{args: "-t raw -I CILIUM_PRE_raw -d 10.0.0.0/16 -m comment --comment cilium: NOTRACK for pod traffic -j CT --notrack"},
			// CILIUM_OUTPUT_raw -s podsCIDR
			{args: "-t raw -I CILIUM_OUTPUT_raw -s 10.0.0.0/16 -m comment --comment cilium: NOTRACK for pod traffic -j CT --notrack"},
			// CILIUM_OUTPUT_raw -d podsCIDR
			{args: "-t raw -I CILIUM_OUTPUT_raw -d 10.0.0.0/16 -m comment --comment cilium: NOTRACK for pod traffic -j CT --notrack"},
		},
	}

	testMgr := &manager{
		sharedCfg: SharedConfig{
			InstallNoConntrackIptRules: true,
			EnableIPv4:                 true,
		},
		ip4tables: mockIp4,
	}

	err := testMgr.addNoTrackPodTrafficRules(mockIp4, podsCIDR)
	assert.NoError(t, err)
	assert.NoError(t, mockIp4.checkExpectations())
}

// TestAllEgressMasqueradeCmdsRandomFully specifically tests the --random-fully
// flag in masquerade rules, covering the iptables masquerading scenario
// previously tested by K8sDatapathConfig Encapsulation context.
func TestAllEgressMasqueradeCmdsRandomFully(t *testing.T) {
	allocRange := "10.0.0.0/16"
	snatDstExclusionCIDR := "192.168.0.0/16"

	// Without --random-fully
	cmdsWithout := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, false, nil, 0)
	for _, cmd := range cmdsWithout {
		assert.NotContains(t, cmd, "--random-fully",
			"Expected no --random-fully when disabled")
	}

	// With --random-fully
	cmdsWith := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR, nil, true, nil, 0)
	for _, cmd := range cmdsWith {
		assert.Contains(t, cmd, "--random-fully",
			"Expected --random-fully when enabled")
	}

	// With --random-fully and specific masquerade interfaces
	cmdsMultiIface := allEgressMasqueradeCmds(allocRange, snatDstExclusionCIDR,
		[]string{"eth0", "ens5"}, true, nil, 0)
	assert.Len(t, cmdsMultiIface, 2, "Expected one rule per masquerade interface")
	for _, cmd := range cmdsMultiIface {
		assert.Contains(t, cmd, "--random-fully",
			"Expected --random-fully when enabled with multiple interfaces")
	}
}

func TestInstallMasqueradeRouteSourceRules(t *testing.T) {
	routes := []netlink.Route{
		{Dst: mustParseCIDR("0.0.0.0/0"), Src: net.ParseIP("198.18.4.4"), LinkIndex: 0, Family: 2},
		{Dst: mustParseCIDR("10.0.0.0/16"), Src: net.ParseIP("10.0.0.1"), LinkIndex: 5, Family: 2},
		{Dst: mustParseCIDR("10.0.1.0/24"), Src: net.ParseIP("10.0.1.1"), LinkIndex: 5, Family: 2},
	}

	mockProg := &mockIptables{t: t, prog: "iptables", expectations: []expectation{
		{args: "-t nat -A CILIUM_POST_nat -s 11.0.0.0/24 -d 10.0.1.0/24 -o eth0 -m comment --comment cilium snat non-cluster via source route -j SNAT --to-source 10.0.1.1"},
		{args: "-t nat -A CILIUM_POST_nat -s 11.0.0.0/24 -d 10.0.0.0/16 -o eth0 -m comment --comment cilium snat non-cluster via source route -j SNAT --to-source 10.0.0.1"},
		{args: "-t nat -A CILIUM_POST_nat -s 11.0.0.0/24 ! -d 11.0.0.0/24 ! -o cilium_+ -m comment --comment cilium snat non-cluster via source route -j SNAT --to-source 198.18.4.4"},
	}}

	linkByIndex := func(index int) (netlink.Link, error) {
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 5}}, nil
	}

	mgr := &manager{}
	err := mgr.installMasqueradeRouteSourceRules(
		mockProg, routes, linkByIndex,
		[]string{"eth0"}, "11.0.0.0/24", "11.0.0.0/24",
	)
	require.NoError(t, err)
	require.NoError(t, mockProg.checkExpectations())
}
func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// TestInstallMasqueradeRulesHostSNATPortRange verifies that when
// NATExcludedPorts contains a port above the SNAT floor (e.g. WireGuard
// 51871), the host-side SNAT rules are split into port-range segments so the
// kernel NAT allocator can never pick that port.
//
// This is a regression test for the failure described in the problem report:
// with VXLAN tunneling + kube-proxy, the host-side SNAT path previously
// emitted unconstrained "-j SNAT --to-source IP" rules that allowed the kernel
// NAT allocator to pick port 8472 (VXLAN), causing TFTP timeouts.
//
// For WireGuard (51871 > 32768) the fix emits two rules per SNAT site:
//
//	rule 1: statistic --every 2 --packet 0 → SNAT --to-source IP:32768-51870
//	rule 2:                                 → SNAT --to-source IP:51872-65535
func TestInstallMasqueradeRulesHostSNATPortRange(t *testing.T) {
	const (
		hostIP       = "10.244.1.1"
		allocRange   = "10.244.1.0/24"
		snatExclCIDR = "10.244.0.0/16"
		wgPort       = uint16(51871)
		minPort      = uint16(32768)
	)

	var recorded []string
	captureProg := &capturingMockIptables{
		mockIptables: mockIptables{t: t, prog: "iptables"},
		sink:         &recorded,
	}

	mgr := &manager{
		sharedCfg: SharedConfig{
			TunnelingEnabled:     true,
			EnableEndpointRoutes: false,
			NATExcludedPorts:     []uint16{wgPort},
			NATMinSNATPort:       minPort,
		},
		ip4tables: captureProg,
		ip6tables: &mockIptables{t: t, prog: "ip6tables"},
	}

	err := mgr.installMasqueradeRules(
		captureProg,
		nil,
		"cilium_host",
		snatExclCIDR,
		allocRange,
		hostIP,
	)
	require.NoError(t, err)

	lo := fmt.Sprintf("%s:%d-%d", hostIP, minPort, wgPort-1)
	hi := fmt.Sprintf("%s:%d-%d", hostIP, wgPort+1, 65535)
	statistic := "-m statistic --mode nth --every 2 --packet 0"

	// Each of the three host-side SNAT comment strings should have both the
	// lower-segment rule (with statistic, for tcp or udp) and the upper-segment
	// rule, plus a plain catch-all for non-TCP/UDP protocols.
	comments := []string{
		"cilium host->cluster masquerade",
		"cilium host->cluster from 127.0.0.1 masquerade",
		"hairpin traffic that originated from a local pod",
	}

	for _, comment := range comments {
		foundLo, foundHi, foundCatchAll := false, false, false
		for _, r := range recorded {
			if !strings.Contains(r, comment) {
				continue
			}

			if strings.Contains(r, statistic) && strings.Contains(r, "--to-source "+lo) {
				foundLo = true
			}

			if !strings.Contains(r, "statistic") && strings.Contains(r, "--to-source "+hi) {
				foundHi = true
			}

			// Catch-all: plain SNAT with no port range (for non-TCP/UDP protocols).
			if strings.HasSuffix(r, "--to-source "+hostIP) {
				foundCatchAll = true
			}
		}

		require.True(t, foundLo, "missing lower-segment SNAT rule for %q", comment)
		require.True(t, foundHi, "missing upper-segment SNAT rule for %q", comment)
		require.True(t, foundCatchAll, "missing catch-all SNAT rule for %q", comment)
	}
}

// capturingMockIptables wraps mockIptables and records every runProg call
// into sink without enforcing expectations ordering.
type capturingMockIptables struct {
	mockIptables
	sink *[]string
}

func (c *capturingMockIptables) runProg(args []string) error {
	*c.sink = append(*c.sink, strings.Join(args, " "))
	return nil
}

func (c *capturingMockIptables) runProgOutput(args []string) (string, error) {
	*c.sink = append(*c.sink, strings.Join(args, " "))
	return "", nil
}

type stubWGConfig struct{ enabled bool }

func (s stubWGConfig) Enabled() bool { return s.enabled }

// ── TestBuildIptablesNATExcludedPorts ─────────────────────────────────────────

// TestBuildIptablesNATExcludedPorts verifies that buildIptablesNATExcludedPorts
// produces the correct sorted port list for every combination of features that
// contribute a Cilium-owned kernel socket.
func TestBuildIptablesNATExcludedPorts(t *testing.T) {
	vxlan := tunnel.NewTestConfig(tunnel.VXLAN)   // port 8472
	geneve := tunnel.NewTestConfig(tunnel.Geneve) // port 6081
	noTun := tunnel.NewTestConfig(tunnel.Disabled)

	wgOn := stubWGConfig{enabled: true}
	wgOff := stubWGConfig{enabled: false}

	tests := []struct {
		name string
		tun  tunnel.Config
		wg   stubWGConfig
		want []uint16
	}{
		{
			name: "no features — empty list",
			tun:  noTun, wg: wgOff,
			want: nil,
		},
		{
			name: "VXLAN only",
			tun:  vxlan, wg: wgOff,
			want: []uint16{8472},
		},
		{
			name: "Geneve only",
			tun:  geneve, wg: wgOff,
			want: []uint16{6081},
		},
		{
			name: "WireGuard only",
			tun:  noTun, wg: wgOn,
			want: []uint16{wgTypes.ListenPort}, // 51871
		},
		{
			name: "VXLAN + WireGuard — sorted",
			tun:  vxlan, wg: wgOn,
			want: []uint16{8472, wgTypes.ListenPort},
		},
		{
			name: "Geneve + WireGuard — sorted",
			tun:  geneve, wg: wgOn,
			want: []uint16{6081, wgTypes.ListenPort},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildIptablesNATExcludedPorts(tt.tun, tt.wg)
			require.Equal(t, tt.want, got)

			// Verify the output is sorted (monotonically increasing).
			for i := 1; i < len(got); i++ {
				require.Less(t, got[i-1], got[i], "ports not sorted at index %d", i)
			}
		})
	}
}

func TestBuildSNATPortSegments(t *testing.T) {
	tests := []struct {
		name           string
		excluded       []uint16
		natMinSNATPort uint16
		wantSegs       []snatPortSegment
	}{
		{
			name:           "no excluded ports — single full segment",
			excluded:       nil,
			natMinSNATPort: 32768,
			wantSegs:       []snatPortSegment{{32768, 65535}},
		},
		{
			name:           "excluded port in the middle",
			excluded:       []uint16{40000},
			natMinSNATPort: 32768,
			wantSegs:       []snatPortSegment{{32768, 39999}, {40001, 65535}},
		},
		{
			name:           "excluded port below floor — ignored, single full segment",
			excluded:       []uint16{8472},
			natMinSNATPort: 32768,
			wantSegs:       []snatPortSegment{{32768, 65535}},
		},
		{
			name:           "excluded port at floor",
			excluded:       []uint16{32768},
			natMinSNATPort: 32768,
			wantSegs:       []snatPortSegment{{32769, 65535}},
		},
		{
			name:           "excluded port at ceiling",
			excluded:       []uint16{65535},
			natMinSNATPort: 32768,
			wantSegs:       []snatPortSegment{{32768, 65534}},
		},
		{
			name:           "two excluded ports",
			excluded:       []uint16{40000, 51871},
			natMinSNATPort: 32768,
			wantSegs:       []snatPortSegment{{32768, 39999}, {40001, 51870}, {51872, 65535}},
		},
		{
			name:           "excluded port exactly at natMinSNATPort and above",
			excluded:       []uint16{32768, 32769},
			natMinSNATPort: 32768,
			wantSegs:       []snatPortSegment{{32770, 65535}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSNATPortSegments(tt.excluded, tt.natMinSNATPort)
			require.Equal(t, tt.wantSegs, got)
		})
	}
}

func TestSNATTargetWithPortRange(t *testing.T) {
	seg := &snatPortSegment{32768, 65535}
	tests := []struct {
		name string
		ip   string
		seg  *snatPortSegment
		want string
	}{
		{
			name: "IPv4 with segment",
			ip:   "10.0.1.1",
			seg:  seg,
			want: "10.0.1.1:32768-65535",
		},
		{
			name: "IPv4 no segment",
			ip:   "10.0.1.1",
			seg:  nil,
			want: "10.0.1.1",
		},
		{
			name: "IPv6 with segment — must be bracketed",
			ip:   "fd00::1",
			seg:  seg,
			want: "[fd00::1]:32768-65535",
		},
		{
			name: "IPv6 no segment",
			ip:   "fd00::1",
			seg:  nil,
			want: "fd00::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := snatTargetWithPortRange(tt.ip, tt.seg)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestHostSNATCmds(t *testing.T) {
	preArgs := []string{"-t", "nat", "-A", "CILIUM_POST_nat", "-o", "cilium_host"}
	comment := "cilium host->cluster masquerade"
	ip := "10.244.1.1"

	join := func(cmds [][]string) []string {
		out := make([]string, len(cmds))
		for i, c := range cmds {
			out[i] = strings.Join(c, " ")
		}
		return out
	}

	t.Run("no excluded ports — single plain SNAT rule", func(t *testing.T) {
		cmds := hostSNATCmds(preArgs, comment, ip, nil, 32768)
		require.Len(t, cmds, 1)
		joined := join(cmds)
		require.Contains(t, joined[0], "--to-source 10.244.1.1")
		require.NotContains(t, joined[0], "statistic")
		require.NotContains(t, joined[0], "32768")
	})

	t.Run("excluded port below floor — single plain SNAT rule", func(t *testing.T) {
		cmds := hostSNATCmds(preArgs, comment, ip, []uint16{8472}, 32768)
		require.Len(t, cmds, 1)
		joined := join(cmds)
		require.Contains(t, joined[0], "--to-source 10.244.1.1")
		require.NotContains(t, joined[0], "statistic")
	})

	t.Run("single excluded port in range — per-protocol rules + catch-all", func(t *testing.T) {
		// 1 excluded port → 2 segments → 2 tcp + 2 udp + 1 catch-all = 5 rules.
		cmds := hostSNATCmds(preArgs, comment, ip, []uint16{51871}, 32768)
		require.Len(t, cmds, 5)
		joined := join(cmds)
		// tcp lower segment
		require.Contains(t, joined[0], "-p tcp")
		require.Contains(t, joined[0], "statistic --mode nth --every 2 --packet 0")
		require.Contains(t, joined[0], "--to-source 10.244.1.1:32768-51870")
		// tcp upper segment
		require.Contains(t, joined[1], "-p tcp")
		require.NotContains(t, joined[1], "statistic")
		require.Contains(t, joined[1], "--to-source 10.244.1.1:51872-65535")
		// udp lower segment
		require.Contains(t, joined[2], "-p udp")
		require.Contains(t, joined[2], "statistic --mode nth --every 2 --packet 0")
		require.Contains(t, joined[2], "--to-source 10.244.1.1:32768-51870")
		// udp upper segment
		require.Contains(t, joined[3], "-p udp")
		require.NotContains(t, joined[3], "statistic")
		require.Contains(t, joined[3], "--to-source 10.244.1.1:51872-65535")
		// catch-all (no protocol, no port range)
		require.NotContains(t, joined[4], "-p tcp")
		require.NotContains(t, joined[4], "-p udp")
		require.Contains(t, joined[4], "--to-source 10.244.1.1")
		require.NotContains(t, joined[4], "32768")
	})

	t.Run("two excluded ports — per-protocol rules + catch-all", func(t *testing.T) {
		// 2 excluded ports → 3 segments → 3 tcp + 3 udp + 1 catch-all = 7 rules.
		cmds := hostSNATCmds(preArgs, comment, ip, []uint16{40000, 51871}, 32768)
		require.Len(t, cmds, 7)
		joined := join(cmds)
		require.Contains(t, joined[0], "-p tcp")
		require.Contains(t, joined[0], "--every 3 --packet 0")
		require.Contains(t, joined[0], "--to-source 10.244.1.1:32768-39999")
		require.Contains(t, joined[1], "-p tcp")
		require.Contains(t, joined[1], "--every 2 --packet 0")
		require.Contains(t, joined[1], "--to-source 10.244.1.1:40001-51870")
		require.Contains(t, joined[2], "-p tcp")
		require.NotContains(t, joined[2], "statistic")
		require.Contains(t, joined[2], "--to-source 10.244.1.1:51872-65535")
		require.Contains(t, joined[3], "-p udp")
		require.Contains(t, joined[4], "-p udp")
		require.Contains(t, joined[5], "-p udp")
		// catch-all
		require.NotContains(t, joined[6], "-p tcp")
		require.NotContains(t, joined[6], "-p udp")
		require.Contains(t, joined[6], "--to-source 10.244.1.1")
	})

	t.Run("IPv6 address is bracketed in --to-source", func(t *testing.T) {
		cmds := hostSNATCmds(preArgs, comment, "fd00::1", []uint16{51871}, 32768)
		require.Len(t, cmds, 5)
		joined := join(cmds)
		require.Contains(t, joined[0], "--to-source [fd00::1]:32768-51870")
		require.Contains(t, joined[1], "--to-source [fd00::1]:51872-65535")
	})

	t.Run("VXLAN port 8472 below floor — plain SNAT, no split", func(t *testing.T) {
		// This is the exact config from the bug report: VXLAN tunnel, kube-proxy mode.
		// 8472 < 32768 so effectiveExcluded == 0 → single unconstrained rule.
		// The floor alone protects against picking 8472 via --to-source IP:32768-65535
		// would be better, but backwards compatibility requires no port range here.
		cmds := hostSNATCmds(preArgs, comment, ip, []uint16{8472}, 32768)
		require.Len(t, cmds, 1)
		joined := join(cmds)
		require.Contains(t, joined[0], "--to-source 10.244.1.1")
		require.NotContains(t, joined[0], "statistic")
	})
}
