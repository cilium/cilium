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

// +build !privileged_tests

package cassandra

import (
	"encoding/hex"
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

type CassandraSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&CassandraSuite{})

// Set up access log server and Library instance for all the test cases
func (s *CassandraSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *CassandraSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *CassandraSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *CassandraSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

// util function used for Cassandra tests, as we have cassandra requests
// as hex strings
func hexData(c *C, dataHex ...string) [][]byte {
	data := make([][]byte, 0, len(dataHex))
	for i := range dataHex {
		dataRaw, err := hex.DecodeString(dataHex[i])
		c.Assert(err, IsNil)
		data = append(data, dataRaw)
	}
	return data
}

func (s *CassandraSuite) TestCassandraOnDataNoHeader(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "no-policy")
	data := hexData(c, "0400")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.MORE, 9-len(data[0]))
}

func (s *CassandraSuite) TestCassandraOnDataOptionsReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp6"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "query_action"
			  value: "select"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp6")

	data := hexData(c, "040000000500000000")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)
}

// this passes a large query request that is missing just the last byte
func (s *CassandraSuite) TestCassandraOnDataPartialReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp5"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp5")
	data := hexData(c, "0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c270001")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.MORE, 1)
}

func (s *CassandraSuite) TestCassandraOnDataQueryReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp4"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp4")
	data := hexData(c, "0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)
}

func (s *CassandraSuite) TestCassandraOnDataSplitQueryReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp3"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp3")
	data := hexData(c, "04000004070000007600", "00006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0])+len(data[1]),
		proxylib.MORE, 9)
}

func (s *CassandraSuite) TestCassandraOnDataMultiReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp2"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp2")

	data := hexData(c, "040000000500000000",
		"0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.PASS, len(data[1]),
		proxylib.MORE, 9)
}

func (s *CassandraSuite) TestSimpleCassandraPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "query_table"
			  value: "no-match"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")

	// FIXME: we should just grab this from the cassandra parser itself rather than duplicating here.
	unauthMsgBase := []byte{
		0x84,     // version (updated to have reply bit set and protocol version 4)
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x0,                 // opcode error (uint8)
		0x0, 0x0, 0x0, 0x1a, // request length (uint32) - update if text changes
		0x0, 0x0, 0x21, 0x00, // 'unauthorized error code' 0x2100 (uint32)
		0x0, 0x14, // length of error msg (uint16)  - update if text changes
		'R', 'e', 'q', 'u', 'e', 's', 't', ' ', 'U', 'n', 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd',
	}

	data := hexData(c, "040000000500000000",
		"0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, unauthMsgBase,
		proxylib.PASS, len(data[0]),
		proxylib.DROP, len(data[1]),
		proxylib.MORE, 9)

	// All passes are not access-logged
	s.checkAccessLogs(c, 0, 1)
}
