// Copyright 2018 Authors of Cilium
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

package redis

import (
	"testing"

	// "github.com/cilium/cilium/pkg/logging"
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

type RedisSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&RedisSuite{})

// Set up access log server and Library instance for all the test cases
func (s *RedisSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *RedisSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *RedisSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *RedisSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func (s *RedisSuite) TestRedisBasicInline(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "rp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "redis"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "key"
			  value: "mykey"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "redis", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "rp1")
	data := [][]byte{[]byte("SET mykey \"foo\"\r\n")}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, len(data[0]))
}

func (s *RedisSuite) TestRedisInlineMore(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "rp2"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "redis"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "key"
			  value: "mykey"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "redis", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "rp2")
	data := [][]byte{[]byte("SET mykey \"foo\"\r\nGET")}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, (len(data[0]) - 3),
		proxylib.MORE, 1)
}

func (s *RedisSuite) TestRedisInlineTwoCmds(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "rp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "redis"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "key"
			  value: "mykey"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "redis", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "rp3")
	cmd1 := "SET mykey \"foo\"\r\n"
	cmd2 := "GET mykey\r\n"
	data := [][]byte{[]byte(cmd1 + cmd2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(cmd1),
		proxylib.PASS, len(cmd2))
}

func (s *RedisSuite) TestRedisInlineSimpleCmdPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "rp4"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "redis"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "cmd"
			  value: "set"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "redis", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "rp4")

	cmd1 := "SET mykey \"foo\"\r\n"
	cmd2 := "GET mykey\r\n"
	data := [][]byte{[]byte(cmd1 + cmd2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(accessDeniedStr),
		proxylib.PASS, len(cmd1),
		proxylib.DROP, len(cmd2))

	// TODO:  check for injected error in reply
}

func (s *RedisSuite) TestRedisInlineSimpleKeyPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "rp4"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "redis"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "key"
			  value: "users.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "redis", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "rp4")

	cmd1 := "GET users1111\r\n"
	cmd2 := "GET mykey\r\n"
	data := [][]byte{[]byte(cmd1 + cmd2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(accessDeniedStr),
		proxylib.PASS, len(cmd1),
		proxylib.DROP, len(cmd2))

}

func (s *RedisSuite) TestRedisArraySimpleCmdPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "rp5"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "redis"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "cmd"
			  value: "LLEN"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "redis", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "rp5")

	data := [][]byte{[]byte("*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n")}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))

}

func (s *RedisSuite) TestRedisArrayMultipleCmdPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "rp6"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "redis"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "cmd"
			  value: "LLEN"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "redis", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "rp6")

	cmd1 := "*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n"
	cmd2 := "*2\r\n$3\r\nGET\r\n$6\r\nmylist\r\n"
	data := [][]byte{[]byte(cmd1 + cmd2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(accessDeniedStr),
		proxylib.PASS, len(cmd1),
		proxylib.DROP, len(cmd2))

}
