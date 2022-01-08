// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package tidb

import (
	"testing"

	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
	// "github.com/cilium/cilium/pkg/logging"
	// "fmt"
	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type TiDBSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&TiDBSuite{})

// Set up access log server and Library instance for all the test cases
func (s *TiDBSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *TiDBSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *TiDBSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *TiDBSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func (s *TiDBSuite) TestTiDBOnDataInjection(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "tidb"
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
	conn := s.ins.CheckNewConnectionOK(c, "tidb", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp3")
	// request body
	msg1 := "READ ssss\r\n"
	data := [][]byte{[]byte(msg1)}
	// []byte("") is the expectedResult
	conn.CheckOnDataOK(c, false, false, &data, []byte(""), // expect result
		proxylib.PASS, len(msg1))
	msg2 := "WRITE yyyyy\r\n"
	data = [][]byte{[]byte(msg2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"), // expect result
		proxylib.DROP, len(msg2)) // ops result, length)
}
