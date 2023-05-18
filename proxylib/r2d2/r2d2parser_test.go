// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package r2d2

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type R2d2Suite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&R2d2Suite{})

// Set up access log server and Library instance for all the test cases
func (s *R2d2Suite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *R2d2Suite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *R2d2Suite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func (s *R2d2Suite) TestR2d2OnDataIncomplete(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "no-policy")
	data := [][]byte{[]byte("READ xssss")}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
}

func (s *R2d2Suite) TestR2d2OnDataBasicPass(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1 := "READ sssss\r\n"
	msg2 := "WRITE sssss\r\n"
	msg3 := "HALT\r\n"
	msg4 := "RESET\r\n"
	data := [][]byte{[]byte(msg1 + msg2 + msg3 + msg4)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(msg1),
		proxylib.PASS, len(msg2),
		proxylib.PASS, len(msg3),
		proxylib.PASS, len(msg4),
		proxylib.MORE, 1)
}

func (s *R2d2Suite) TestR2d2OnDataMultipleReq(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1Part1 := "RE"
	msg1Part2 := "SET\r\n"
	data := [][]byte{[]byte(msg1Part1), []byte(msg1Part2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(msg1Part1+msg1Part2),
		proxylib.MORE, 1)
}

func (s *R2d2Suite) TestR2d2OnDataAllowDenyCmd(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "cmd"
			  value: "READ"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1 := "READ xssss\r\n"
	msg2 := "WRITE xssss\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
}

func (s *R2d2Suite) TestR2d2OnDataAllowDenyRegex(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "r2d2"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "file"
			  value: "s.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "r2d2", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	msg1 := "READ ssss\r\n"
	msg2 := "WRITE yyyyy\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
}
