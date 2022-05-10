// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package main

import (
	"fmt"
	"testing"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
	_ "github.com/cilium/cilium/proxylib/testparsers"
)

const debug = false

func TestOpenModule(t *testing.T) {
	mod1 := OpenModule([][2]string{}, debug)
	if mod1 == 0 {
		t.Error("OpenModule() with empty params failed")
	} else {
		defer CloseModule(mod1)
	}
	mod2 := OpenModule([][2]string{}, debug)
	if mod2 == 0 {
		t.Error("OpenModule() with empty params failed")
	} else {
		defer CloseModule(mod2)
	}
	if mod2 != mod1 {
		t.Error("OpenModule() with empty params called again opened a new module")
	}

	mod3 := OpenModule([][2]string{{"dummy-key", "dummy-value"}, {"key2", "value2"}}, debug)
	if mod3 != 0 {
		t.Error("OpenModule() with unknown params accepted")
		defer CloseModule(mod3)
	}

	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod4 := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod4 == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod4)
	}
	if mod4 == mod1 {
		t.Error("OpenModule() should have returned a different module")
	}

	mod5 := OpenModule([][2]string{{"access-log-path", logServer.Path}, {"node-id", "host~127.0.0.1~libcilium~localdomain"}}, debug)
	if mod5 == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod5)
	}
	if mod5 == mod1 || mod5 == mod2 || mod5 == mod3 || mod5 == mod4 {
		t.Error("OpenModule() should have returned a different module")
	}
}

func TestOnNewConnection(t *testing.T) {
	mod := OpenModule([][2]string{}, debug)
	if mod == 0 {
		t.Error("OpenModule() with empty params failed")
	} else {
		defer CloseModule(mod)
	}

	// Unkhown parser
	CheckOnNewConnection(t, mod, "invalid-parser-should-not-exist", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1", 80, proxylib.UNKNOWN_PARSER, 0)

	// Non-numeric destination port
	CheckOnNewConnection(t, mod, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:XYZ", "1.1.1.1",
		80, proxylib.INVALID_ADDRESS, 0)

	// Missing Destination port
	CheckOnNewConnection(t, mod, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2", "1.1.1.1",
		80, proxylib.INVALID_ADDRESS, 0)

	// Zero Destination port is reserved for wildcarding
	CheckOnNewConnection(t, mod, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:0", "1.1.1.1",
		80, proxylib.INVALID_ADDRESS, 0)

	// L7 parser rejecting the connection based on connection metadata
	CheckOnNewConnection(t, mod, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "invalid-policy",
		80, proxylib.POLICY_DROP, 0)

	// Using test parser
	CheckOnNewConnection(t, mod, "test.passer", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		80, proxylib.OK, 1)

	// 2nd connection
	CheckOnNewConnection(t, mod, "test.passer", 12345678901234567890, false, 2, 1, "10.0.0.2:80", "1.1.1.1:34567", "2.2.2.2",
		80, proxylib.OK, 2)

	CheckClose(t, 1, nil, 2)

	CheckClose(t, 12345678901234567890, nil, 1)
}

func checkAccessLogs(t *testing.T, logServer *test.AccessLogServer, expPasses, expDrops int) {
	t.Helper()
	passes, drops := 0, 0
	nWaits := 0
	done := false
	timer, timerDone := inctimer.New()
	defer timerDone()
	// Loop until done or when the timeout has ticked 100 times without any logs being received
	for !done && nWaits < 100 {
		select {
		case entryType := <-logServer.Logs:
			if entryType == cilium.EntryType_Denied {
				drops++
			} else {
				passes++
			}
			// Start the timeout again (for upto 5 seconds)
			nWaits = 0
		case <-timer.After(50 * time.Millisecond):
			// Count the number of times we have waited since the last log was received
			nWaits++
			// Finish when expected number of passes and drops have been collected
			// and there are no more logs in the channel for 50 milliseconds
			if passes == expPasses && drops == expDrops {
				done = true
			}
		}
	}

	if !(passes == expPasses && drops == expDrops) {
		t.Errorf("OnData: Unexpected access log entries, expected %d passes (got %d) and %d drops (got %d).", expPasses, passes, expDrops, drops)
	}
}

func TestOnDataNoPolicy(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		30, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3 := "No policy\n", "Dropped\n", "foo"
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(line1), []byte(line2 + line3)}, []ExpFilterOp{
		{proxylib.DROP, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.MORE, 1},
	}, proxylib.OK, "Line dropped: "+line1+"Line dropped: "+line2)

	// No new input
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(line3)}, []ExpFilterOp{
		{proxylib.MORE, 1},
	}, proxylib.OK, "")

	// Empty
	CheckOnData(t, 1, false, false, &[][]byte{}, []ExpFilterOp{}, proxylib.OK, "")

	expPasses, expDrops := 0, 2
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

type PanicParserFactory struct{}

var panicParserFactory *PanicParserFactory

type PanicParser struct {
	connection *proxylib.Connection
}

func (p *PanicParserFactory) Create(connection *proxylib.Connection) interface{} {
	logrus.Debugf("PanicParserFactory: Create: %v", connection)
	return &PanicParser{connection: connection}
}

//
// Parses individual lines and verifies them against the policy
//
func (p *PanicParser) OnData(reply, endStream bool, data [][]byte) (proxylib.OpType, int) {
	if !reply {
		panic(fmt.Errorf("PanicParser OnData(reply=%t, endStream=%t, data=%v) panicing...", reply, endStream, data))
	}
	return proxylib.NOP, 0
}

func TestOnDataPanic(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	// This registation will remain after this test.
	proxylib.RegisterParserFactory("test.panicparser", panicParserFactory)

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.panicparser", 11, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		30, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	CheckOnData(t, 11, false, false, &[][]byte{[]byte("foo")}, []ExpFilterOp{}, proxylib.PARSER_ERROR, "")

	expPasses, expDrops := 0, 1
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 11, buf, 1)
}

func insertPolicyText(t *testing.T, mod uint64, version string, policies []string) bool {
	return insertPolicyTextRaw(t, mod, version, policies, "") == nil
}

func insertPolicyTextRaw(t *testing.T, mod uint64, version string, policies []string, expectFail string) error {
	instance := proxylib.FindInstance(mod)
	if instance == nil {
		t.Errorf("Policy Update failed to get the library instance.")
	} else {
		return instance.InsertPolicyText(version, policies, expectFail)
	}
	return nil
}

func TestUnsupportedL7Drops(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    kafka_rules: <
		      kafka_rules: <
			topic: "Topic"
		      >
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		256, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(data)}, []ExpFilterOp{
		{proxylib.DROP, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.DROP, len(line3)},
		{proxylib.DROP, len(line4)},
	}, proxylib.OK, "Line dropped: "+line1+"Line dropped: "+line2+"Line dropped: "+line3+"Line dropped: "+line4)

	expPasses, expDrops := 0, 4
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

func TestUnsupportedL7DropsGeneric(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "this-parser-does-not-exist"
		    l7_rules: <
		      l7_allow_rules: <
		        rule: <
		          key: "prefix"
		          value: "Beginning"
		        >
		      >
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		256, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(data)}, []ExpFilterOp{
		{proxylib.DROP, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.DROP, len(line3)},
		{proxylib.DROP, len(line4)},
	}, proxylib.OK, "Line dropped: "+line1+"Line dropped: "+line2+"Line dropped: "+line3+"Line dropped: "+line4)

	expPasses, expDrops := 0, 4
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

func TestEnvoyL7DropsGeneric(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "envoy.filter.network.test"
		    l7_rules: <
		      l7_allow_rules: <
		        rule: <
		          key: "action"
		          value: "drop"
		        >
		      >
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		256, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(data)}, []ExpFilterOp{
		{proxylib.DROP, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.DROP, len(line3)},
		{proxylib.DROP, len(line4)},
	}, proxylib.OK, "Line dropped: "+line1+"Line dropped: "+line2+"Line dropped: "+line3+"Line dropped: "+line4)

	expPasses, expDrops := 0, 4
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

func TestTwoRulesOnSamePortFirstNoL7(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 11
		  >
		  rules: <
		    remote_policies: 11
		    http_rules: <
		      http_rules: <
			headers: <
			  name: ":path"
			  exact_match: "/allowed"
			>
		      >
		    >
		  >
		>
		`})
}

func TestTwoRulesOnSamePortFirstNoL7Generic(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 11
		  >
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "test.headerparser"
		    l7_rules: <
		      l7_allow_rules: <
		        rule: <
		          key: "prefix"
		          value: "Beginning"
		        >
		      >
		      l7_allow_rules: <
		        rule: <
		          key: "suffix"
		          value: "End"
		        >
		      >
		    >
		  >
		>
		`})
}

func TestTwoRulesOnSamePortMismatchingL7(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	// This registation will remain after this test.
	proxylib.RegisterL7RuleParser("PortNetworkPolicyRule_HttpRules", func(*cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
		return nil
	})

	err := insertPolicyTextRaw(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 11
		    http_rules: <
		      http_rules: <
			headers: <
			  name: ":path"
			  exact_match: "/allowed"
			>
		      >
		    >
		  >
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "test.headerparser"
		    l7_rules: <
		      l7_allow_rules: <
		        rule: <
		          key: "prefix"
		          value: "Beginning"
		        >
		      >
		      l7_allow_rules: <
		        rule: <
		          key: "suffix"
		          value: "End"
		        >
		      >
		    >
		  >
		>
		`}, "update")
	if err == nil {
		t.Errorf("Expected Policy Update to fail due to mismatching L7 protocols on the same port, but it succeeded")
	} else {
		logrus.Debugf("Expected error: %s", err)
	}
}

func TestSimplePolicy(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "test.headerparser"
		    l7_rules: <
		      l7_allow_rules: <
		        rule: <
		          key: "prefix"
		          value: "Beginning"
		        >
		      >
		      l7_allow_rules: <
		        rule: <
		          key: "suffix"
		          value: "End"
		        >
		      >
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		80, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(data)}, []ExpFilterOp{
		{proxylib.PASS, len(line1)},
		{proxylib.DROP, len(line2)},
		{proxylib.PASS, len(line3)},
		{proxylib.DROP, len(line4)},
	}, proxylib.OK, "Line dropped: "+line2+"Line dropped: "+line4)

	expPasses, expDrops := 2, 2
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

func TestAllowAllPolicy(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "test.headerparser"
		    l7_rules: <
		      l7_allow_rules: <>
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		80, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(data)}, []ExpFilterOp{
		{proxylib.PASS, len(line1)},
		{proxylib.PASS, len(line2)},
		{proxylib.PASS, len(line3)},
		{proxylib.PASS, len(line4)},
	}, proxylib.OK, "")

	expPasses, expDrops := 4, 0
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}

func TestAllowEmptyPolicy(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "test.headerparser"
		  >
		>
		`})

	// Using headertester parser, policy name matches the policy
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		80, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(line1), []byte(line2), []byte(line3), []byte(line4)}, []ExpFilterOp{
		{proxylib.PASS, len(line1)},
		{proxylib.PASS, len(line2)},
		{proxylib.PASS, len(line3)},
		{proxylib.PASS, len(line4)},
	}, proxylib.OK, "")

	// Connection using a different policy name still drops
	CheckOnNewConnection(t, mod, "test.headerparser", 2, true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "2.2.2.2",
		80, proxylib.OK, 2)
	CheckOnData(t, 2, false, false, &[][]byte{[]byte(line1)}, []ExpFilterOp{
		{proxylib.DROP, len(line1)},
	}, proxylib.OK, "Line dropped: "+line1)

	expPasses, expDrops := 4, 1
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 2, buf, 2)
	CheckClose(t, 1, buf, 1)
}

func TestAllowAllPolicyL3Egress(t *testing.T) {
	logServer := test.StartAccessLogServer("access_log.sock", 10)
	defer logServer.Close()

	mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, debug)
	if mod == 0 {
		t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
	} else {
		defer CloseModule(mod)
	}

	//logging.ToggleDebugLogs(true)
	//logrus.SetLevel(logrus.DebugLevel)

	insertPolicyText(t, mod, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 42
		egress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 2
		    l7_proto: "test.headerparser"
		    l7_rules: <
		      l7_allow_rules: <>
		    >
		  >
		>
		`})

	// Using headertester parser
	buf := CheckOnNewConnection(t, mod, "test.headerparser", 1, false, 42, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1",
		80, proxylib.OK, 1)

	// Original direction data, drops with remaining data
	line1, line2, line3, line4 := "Beginning----\n", "foo\n", "----End\n", "\n"
	data := line1 + line2 + line3 + line4
	CheckOnData(t, 1, false, false, &[][]byte{[]byte(data)}, []ExpFilterOp{
		{proxylib.PASS, len(line1)},
		{proxylib.PASS, len(line2)},
		{proxylib.PASS, len(line3)},
		{proxylib.PASS, len(line4)},
	}, proxylib.OK, "")

	expPasses, expDrops := 4, 0
	checkAccessLogs(t, logServer, expPasses, expDrops)

	CheckClose(t, 1, buf, 1)
}
