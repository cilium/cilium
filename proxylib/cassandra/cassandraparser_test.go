// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package cassandra

import (
	"encoding/hex"
	"testing"

	. "gopkg.in/check.v1"

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
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "no-policy")
	data := hexData(c, "0400")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.MORE, 9-len(data[0]))
}

func (s *CassandraSuite) TestCassandraOnDataOptionsReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_action"
			  value: "select"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	data := hexData(c, "040000000500000000")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)
}

// this passes a large query request that is missing just the last byte
func (s *CassandraSuite) TestCassandraOnDataPartialReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	data := hexData(c, "0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c270001")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.MORE, 1)
}

func (s *CassandraSuite) TestCassandraOnDataQueryReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	data := hexData(c, "0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)
}

func (s *CassandraSuite) TestCassandraOnDataSplitQueryReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	data := hexData(c, "04000004070000007600", "00006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0])+len(data[1]),
		proxylib.MORE, 9)
}

func (s *CassandraSuite) TestCassandraOnDataMultiReq(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: ".*"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	data := hexData(c, "040000000500000000",
		"0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.PASS, len(data[1]),
		proxylib.MORE, 9)
}

func (s *CassandraSuite) TestSimpleCassandraPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "no-match"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	unauthMsg := createUnauthMsg(0x4)
	data := hexData(c, "040000000500000000",
		"0400000407000000760000006f53454c45435420636c75737465725f6e616d652c20646174615f63656e7465722c207261636b2c20746f6b656e732c20706172746974696f6e65722c20736368656d615f76657273696f6e2046524f4d2073797374656d2e6c6f63616c205748455245206b65793d276c6f63616c27000100")
	conn.CheckOnDataOK(c, false, false, &data, unauthMsg,
		proxylib.PASS, len(data[0]),
		proxylib.DROP, len(data[1]),
		proxylib.MORE, 9)

	// All passes are not access-logged
	s.checkAccessLogs(c, 0, 1)
}

func createUnauthMsg(streamID byte) []byte {
	unauthMsg := make([]byte, len(unauthMsgBase))
	copy(unauthMsg, unauthMsgBase)
	unauthMsg[0] = 0x84
	unauthMsg[2] = 0x0
	unauthMsg[3] = streamID
	return unauthMsg
}

// this test confirms that we correctly parse and allow a valid batch requests
func (s *CassandraSuite) TestCassandraBatchRequestPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "db1.*"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	batchMsg := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x0d,                // opcode batch (uint8)
		0x0, 0x0, 0x0, 0x3c, // request length of 60 (uint32) - update if body changes
		0x0,      // batch type == logged
		0x0, 0x2, // two batch messages

		// first batch message
		0x0,                 // type: non-prepared query
		0x0, 0x0, 0x0, 0x14, // [long string] length (20)
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M', ' ', 'd', 'b', '1', '.', 't', '1',
		0x0, 0x0, // # of bound values

		// second batch message
		0x0,                 // type: non-prepared query
		0x0, 0x0, 0x0, 0x14, // [long string] length (20)
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M', ' ', 'd', 'b', '1', '.', 't', '2',
		0x0, 0x0, // # of bound values

		0x0, 0x0, // consistency level [short]
		0x0, // batch flags
	}
	data := [][]byte{batchMsg}

	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)

	// batch requests are access-logged individually
	s.checkAccessLogs(c, 2, 0)
}

// this test confirms that we correctly parse and deny a batch request
// if any of the requests are denied.
func (s *CassandraSuite) TestCassandraBatchRequestPolicyDenied(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "db1.*"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	batchMsg := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x0d,                // opcode batch (uint8)
		0x0, 0x0, 0x0, 0x3c, // request length of 60 (uint32) - update if body changes
		0x0,      // batch type == logged
		0x0, 0x2, // two batch messages

		// first batch message
		0x0,                 // type: non-prepared query
		0x0, 0x0, 0x0, 0x14, // [long string] length (20)
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M', ' ', 'd', 'b', '1', '.', 't', '1',
		0x0, 0x0, // # of bound values

		// second batch message (accesses db2.t2, which should be denied)
		0x0,                 // type: non-prepared query
		0x0, 0x0, 0x0, 0x14, // [long string] length (20)
		'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M', ' ', 'd', 'b', '2', '.', 't', '2',
		0x0, 0x0, // # of bound values

		0x0, 0x0, // consistency level [short]
		0x0, // batch flags
	}
	data := [][]byte{batchMsg}

	unauthMsg := createUnauthMsg(0x4)
	conn.CheckOnDataOK(c, false, false, &data, unauthMsg,
		proxylib.DROP, len(data[0]),
		proxylib.MORE, 9)

	// batch requests are access-logged individually
	// Note: in this case, both accesses are denied, as a batch
	// request is either entirely allowed or denied
	s.checkAccessLogs(c, 0, 2)
}

// test batch requests with prepared statements
func (s *CassandraSuite) TestCassandraBatchRequestPreparedStatement(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "db3.*"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	cassParser, ok := (conn.Parser).(*CassandraParser)
	if !ok {
		panic("failed to cast conn.Parser to *CassandraParser\n")
	}
	preparedQueryID1 := "aaaa"
	cassParser.preparedQueryPathByPreparedID[preparedQueryID1] = "/batch/select/db3.t1"
	preparedQueryID2 := "bbbb"
	cassParser.preparedQueryPathByPreparedID[preparedQueryID2] = "/batch/select/db3.t2"

	batchMsg := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x0d,                // opcode batch (uint8)
		0x0, 0x0, 0x0, 0x18, // request length of 60 (uint32) - update if body changes
		0x0,      // batch type == logged
		0x0, 0x2, // two batch messages

		// first batch message
		0x1,      // type: prepared query
		0x0, 0x4, // [short] length (4)
		'a', 'a', 'a', 'a',
		0x0, 0x0, // # of bound values

		// second batch message
		0x1,      // type: non-prepared query
		0x0, 0x4, // [short] length (4)
		'b', 'b', 'b', 'b',
		0x0, 0x0, // # of bound values

		0x0, 0x0, // consistency level [short]
		0x0, // batch flags
	}
	data := [][]byte{batchMsg}

	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)

	// batch requests are access-logged individually
	s.checkAccessLogs(c, 2, 0)
}

// test batch requests with prepared statements, including a deny
func (s *CassandraSuite) TestCassandraBatchRequestPreparedStatementDenied(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "db3.*"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	cassParser, ok := (conn.Parser).(*CassandraParser)
	if !ok {
		panic("failed to cast conn.Parser to *CassandraParser\n")
	}
	preparedQueryID1 := "aaaa"
	cassParser.preparedQueryPathByPreparedID[preparedQueryID1] = "/batch/select/db3.t1"
	preparedQueryID2 := "bbbb"
	cassParser.preparedQueryPathByPreparedID[preparedQueryID2] = "/batch/select/db4.t2"

	batchMsg := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x0d,                // opcode batch (uint8)
		0x0, 0x0, 0x0, 0x18, // request length of 60 (uint32) - update if body changes
		0x0,      // batch type == logged
		0x0, 0x2, // two batch messages

		// first batch message
		0x1,      // type: prepared query
		0x0, 0x4, // [short] length (4)
		'a', 'a', 'a', 'a',
		0x0, 0x0, // # of bound values

		// second batch message (accesses table db4, which should be denied)
		0x1,      // type: non-prepared query
		0x0, 0x4, // [short] length (4)
		'b', 'b', 'b', 'b',
		0x0, 0x0, // # of bound values

		0x0, 0x0, // consistency level [short]
		0x0, // batch flags
	}
	data := [][]byte{batchMsg}

	unauthMsg := createUnauthMsg(0x4)
	conn.CheckOnDataOK(c, false, false, &data, unauthMsg,
		proxylib.DROP, len(data[0]),
		proxylib.MORE, 9)

	// batch requests are access-logged individually
	s.checkAccessLogs(c, 0, 2)
}

// test execute statement, allow request
func (s *CassandraSuite) TestCassandraExecutePreparedStatement(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "db3.*"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	cassParser, ok := (conn.Parser).(*CassandraParser)
	if !ok {
		panic("failed to cast conn.Parser to *CassandraParser\n")
	}
	preparedQueryID1 := "aaaa"
	cassParser.preparedQueryPathByPreparedID[preparedQueryID1] = "/query/select/db3.t1"

	executeMsg := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x0a,                // opcode execute (uint8)
		0x0, 0x0, 0x0, 0x09, // request length  (uint32) - update if body changes

		// Execute request
		0x0, 0x4, // short bytes len (4)
		'a', 'a', 'a', 'a',

		// the rest of this is values that can be ignored by our parser,
		// but we add some here to make sure that we're properly passing
		// based on total request length.
		'x', 'y', 'z',
	}
	data := [][]byte{executeMsg}

	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)

	s.checkAccessLogs(c, 1, 0)
}

// test execute statement with unknown prepared-id
func (s *CassandraSuite) TestCassandraExecutePreparedStatementUnknownID(c *C) {

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp1")

	executeMsg := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x0a,                // opcode execute (uint8)
		0x0, 0x0, 0x0, 0x06, // request length  (uint32) - update if body changes

		// Execute request
		0x0, 0x4, // short bytes len (4)
		'a', 'a', 'a', 'a',
	}
	data := [][]byte{executeMsg}

	unpreparedMsg := createUnpreparedMsg(0x04, []byte{0x0, 0x4}, "aaaa")

	conn.CheckOnDataOK(c, false, false, &data, unpreparedMsg,
		proxylib.DROP, len(data[0]),
		proxylib.MORE, 9)

	s.checkAccessLogs(c, 0, 1)
}

// test parsing of a prepared query reply
func (s *CassandraSuite) TestCassandraPreparedResultReply(c *C) {

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "cp1")

	cassParser, ok := (conn.Parser).(*CassandraParser)
	if !ok {
		panic("failed to cast conn.Parser to *CassandraParser\n")
	}

	// make sure there is a stream-id (4) that matches the request below
	// this would have been populated by a "prepare" request
	cassParser.preparedQueryPathByStreamID[uint16(4)] = "/query/select/db3.t1"

	preparedResultMsg := []byte{
		0x84,     // reply + version
		0x0,      // flags, (uint8)
		0x0, 0x4, // stream-id (uint16) (test request uses 0x0004 as stream ID)
		0x08,                // opcode result (uint8)
		0x0, 0x0, 0x0, 0x16, // request length 22 (uint32) - update if body changes

		// Prepared Result request
		0x0, 0x0, 0x0, 0x4, // [int] result type
		0x0, 0x4, // prepared-id len (short)
		'a', 'a', 'a', 'a', // prepared-id
		0x0, 0x0, 0x0, 0x0, // prepared results flags
		0x0, 0x0, 0x0, 0x0, // column-count
		0x0, 0x0, 0x0, 0x0, // pk-count
	}
	data := [][]byte{preparedResultMsg}

	conn.CheckOnDataOK(c, true, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.MORE, 9)

	// these replies are not access logged
	s.checkAccessLogs(c, 0, 0)
}

// test additional queries
func (s *CassandraSuite) TestCassandraAdditionalQueries(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "db4.t1"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	queries := []string{"CREATE TABLE db4.t1 (f1 varchar, f2 timeuuid, PRIMARY KEY ((f1), f2))",
		"INSERT INTO db4.t1 (f1, f2, f3) values ('dan', now(), 'Cilium!')",
		"UPDATE db4.t1 SET f1 = 'donald' where f2 in (1,2,3)",
		"DROP TABLE db4.t1",
		"TRUNCATE db4.t1",
		"CREATE TABLE IF NOT EXISTS db4.t1 (f1 varchar, PRIMARY KEY(f1))",
	}

	queryMsgBase := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x5, // stream-id (uint16) (test request uses 0x0005 as stream ID)
		0x07,               // opcode query (uint8)
		0x0, 0x0, 0x0, 0x0, // length of request - must be set

		// Query Req
		0x0, 0x0, 0x0, 0x0, // length of query (int) - must be set
		// query string goes here
	}

	data := make([][]byte, len(queries))
	for i := 0; i < len(queries); i++ {
		queryLen := len(queries[i])

		queryMsg := append(queryMsgBase, []byte(queries[i])...)

		// this works as long as query is less than 251 bytes
		queryMsg[8] = byte(4 + queryLen)
		queryMsg[12] = byte(queryLen)

		data[i] = queryMsg
	}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.PASS, len(data[1]),
		proxylib.PASS, len(data[2]),
		proxylib.PASS, len(data[3]),
		proxylib.PASS, len(data[4]),
		proxylib.PASS, len(data[5]),
		proxylib.MORE, 9)

	s.checkAccessLogs(c, 6, 0)
}

// test use query, following by query that does not include the keyspace
func (s *CassandraSuite) TestCassandraUseQuery(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
		    l7_proto: "cassandra"
		    l7_rules: <
		      l7_allow_rules: <
			rule: <
			  key: "query_table"
			  value: "db5.t1"
			>
		      >
		    >
		  >
		>
		`})

	conn := s.ins.CheckNewConnectionOK(c, "cassandra", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")

	// note: the second insert command intentionally does not include a keyspace, so that it will only
	// be allowed if we properly propagate the keyspace from the previous use command
	queries := []string{"USE db5", "INSERT INTO t1 (f1, f2, f3) values ('dan', now(), 'Cilium!')"}

	queryMsgBase := []byte{
		0x04,     // version
		0x0,      // flags, (uint8)
		0x0, 0x5, // stream-id (uint16) (test request uses 0x0005 as stream ID)
		0x07,               // opcode query (uint8)
		0x0, 0x0, 0x0, 0x0, // length of request - must be set

		// Query Req
		0x0, 0x0, 0x0, 0x0, // length of query (int) - must be set
		// query string goes here
	}

	data := make([][]byte, len(queries))
	for i := 0; i < len(queries); i++ {
		queryLen := len(queries[i])

		queryMsg := append(queryMsgBase, []byte(queries[i])...)

		// this works as long as query is less than 251 bytes
		queryMsg[8] = byte(4 + queryLen)
		queryMsg[12] = byte(queryLen)

		data[i] = queryMsg
	}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]),
		proxylib.PASS, len(data[1]),
		proxylib.MORE, 9)

	// use command will not show up in access log, so only expect one msg
	s.checkAccessLogs(c, 1, 0)
}
