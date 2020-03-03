// Copyright 2020 Authors of Cilium
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

package mysql

import (
	"testing"

	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	// log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type MysqlSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&MysqlSuite{})

// Set up access log server and Library instance for all the test cases
func (s *MysqlSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *MysqlSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *MysqlSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *MysqlSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

/* func (s *MysqlSuite) TestMysqlOnDataIncomplete(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "no-policy")
	data := [][]byte{[]byte("select * from a")}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
} */

func (s *MysqlSuite) TestMysqlOnDataBasicPass(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "mysql"
		    l7_rules: <
		      l7_rules: <
		      rule: <
		        key: "query_action"
		        key: "select"
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	msg1 := "select * from a;\r\n"
	data := [][]byte{[]byte(msg1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(msg1),
		proxylib.MORE, 1)
}

/* func (s *MysqlSuite) TestMysqlOnDataMultipleReq(c *C) {

	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "mysql"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	msg1Part1 := "RE"
	msg1Part2 := "SET\r\n"
	data := [][]byte{[]byte(msg1Part1), []byte(msg1Part2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(msg1Part1+msg1Part2),
		proxylib.MORE, 1)
}

func (s *MysqlSuite) TestMysqlOnDataAllowDenyCmd(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp2"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "mysql"
            l7_rules: <
                l7_rules: <
			        rule: <
			            key: "cmd"
			            value: "READ"
			        >
                >
            >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp2")
	msg1 := "READ xssss\r\n"
	msg2 := "WRITE xssss\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
}

func (s *MysqlSuite) TestMysqlOnDataAllowDenyRegex(c *C) {

	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "mysql"
            l7_rules: <
                l7_rules: <
			        rule: <
			            key: "file"
			            value: "s.*"
			        >
                >
            >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "mysql", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp3")
	msg1 := "READ ssss\r\n"
	msg2 := "WRITE yyyyy\r\n"
	data := [][]byte{[]byte(msg1 + msg2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte("ERROR\r\n"),
		proxylib.PASS, len(msg1),
		proxylib.DROP, len(msg2),
		proxylib.MORE, 1)
} */
