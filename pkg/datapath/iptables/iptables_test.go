// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"fmt"
	"strings"
	"testing"
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
}

func (ipt *mockIptables) getProg() string {
	return ipt.prog
}

func (ipt *mockIptables) getIpset() string {
	return ipt.ipset
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
}

func TestGetProxyPort(t *testing.T) {
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
	port := mockManager.doGetProxyPort(mockIp4tables, "cilium-dns-egress")
	if port != uint16(43479) {
		t.Fatalf("expected port number %d, got %d", uint16(43479), port)
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
TPROXY     tcp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd5a90200 /* cilium: TPROXY to host cilium-random-proxy proxy */ TPROXY redirect 0.0.0.0:43477 mark 0x200/0xffffffff
TPROXY     udp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd5a90200 /* cilium: TPROXY to host cilium-random-proxy proxy */ TPROXY redirect 0.0.0.0:43477 mark 0x200/0xffffffff
TPROXY     tcp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd7a90200 /* cilium: TPROXY to host cilium-random-proxy proxy */ TPROXY redirect 0.0.0.0:43479 mark 0x200/0xffffffff
TPROXY     udp  --  0.0.0.0/0            0.0.0.0/0            mark match 0xd7a90200 /* cilium: TPROXY to host cilium-random-proxy proxy */ TPROXY redirect 0.0.0.0:43479 mark 0x200/0xffffffff
`),
		},
	}

	port = mockManager.doGetProxyPort(mockIp4tables, "cilium-random-proxy")
	if port != uint16(43479) {
		t.Fatalf("expected port number %d, got %d", uint16(43479), port)
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
