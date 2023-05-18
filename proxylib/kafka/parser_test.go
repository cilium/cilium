// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kafka

import (
	"encoding/hex"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	logging.SetLogLevelToDebug()
	// flowdebug.Enable()
	TestingT(t)
}

type KafkaSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&KafkaSuite{})

// Set up access log server and Library instance for all the test cases
func (s *KafkaSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *KafkaSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *KafkaSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *KafkaSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

// util function used for Kafka tests, as we may have Kafka requests
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

func (s *KafkaSuite) TestKafkaOnDataNoHeader(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1, 2, "1.1.1.1:34567", "10.0.0.2:80", "no-policy")
	data := hexData(c, "")
	conn.CheckOnDataOK(c, false, false, &data, []byte{})
	data = hexData(c, "00")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 7)
	data = hexData(c, "0000")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 6)
	data = hexData(c, "000001")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 5)
	data = hexData(c, "00000100")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 4)
	data = hexData(c, "00010000010203")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
	data = hexData(c, "000100000102030405060708")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 65536-8)
}

var testMessage1 = "0000" // length = 42 (0x2a), first half

var testMessage2 = "002a" + // length = 42 (0x2a), 2nd half
	"0000" + // APIkey = 0 (Produce)
	"0003" + // Version = 3 (KafkaV3)
	"00010001" + // CorrelationID = 65537
	"0003414243" + // ClientID (string) "ABC"
	"000144" + // TransactionalID (string) "D"
	"0000" + // RequiredAcks = 0
	"000003" // Timeout = 1000 ms, first 3 bytes

var testMessage3 = "E8" + // Timeout = 1000 ms, last byte
	"00000002" + // Array length = 2
	"00024546" + // - TopicName (string) "EF"
	"00000000" + //   ProduceReqPartition array length = 0
	"00024748" + // - TopicName (string) "GH"
	"00000000" //   ProduceReqPartition array length = 0

var testMessage3Fail = "E8" + // Timeout = 1000 ms, last byte
	"20000002" + // Array length = 0x20000002 (should cause failure
	"00024546" + // - TopicName (string) "EF"
	"00000000" + //   ProduceReqPartition array length = 0
	"00024748" + // - TopicName (string) "GH"
	"00000000" //   ProduceReqPartition array length = 0

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderMinimalPolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "face::feed"
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, 4+42)
}

func (s *KafkaSuite) TestKafkaOnDataInvalidMessage(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3Fail)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.ERROR, int(proxylib.ERROR_INVALID_FRAME_TYPE))
	s.checkAccessLogs(c, 0, 1)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderSimplePolicy(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, 4+42)
	s.checkAccessLogs(c, 1, 0)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithPolicyDrop(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: -1
			topic: "EF"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3, "0000")

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data,
		// Error response:
		[]byte{0x0, 0x0, 0x0, 0x1c, // length
			0x0, 0x1, 0x0, 0x1, // Correlation ID (65537)
			0x0, 0x0, 0x0, 0x2, // 2 topics
			0x0, 0x2, 0x45, 0x46, // name: "EF"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x2, 0x47, 0x48, // name: "GH"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x0, 0x0, 0x0}, // ThrottleTime
		proxylib.DROP, 4+42,
		proxylib.MORE, 6)
	s.checkAccessLogs(c, 0, 1)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithPolicyAllow(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: -1
			topic: "EF"
		      >
		      kafka_rules: <
			api_version: -1
			topic: "GH"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, 4+42)
	s.checkAccessLogs(c, 1, 0)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithClientIDAllow(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: -1
			topic: "EF"
			client_id: "ABC"
		      >
		      kafka_rules: <
			api_version: -1
			topic: "GH"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, 4+42)
	s.checkAccessLogs(c, 1, 0)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithClientID(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: -1
			client_id: "ABC"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, 4+42)
	s.checkAccessLogs(c, 1, 0)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithApiKeys(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: -1
			api_keys: 0
			client_id: "ABC"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, 4+42)
	s.checkAccessLogs(c, 1, 0)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithApiKeysMismatch(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: -1
			api_keys: 1
			client_id: "ABC"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data,
		// Error response:
		[]byte{0x0, 0x0, 0x0, 0x1c, // length
			0x0, 0x1, 0x0, 0x1, // Correlation ID (65537)
			0x0, 0x0, 0x0, 0x2, // 2 topics
			0x0, 0x2, 0x45, 0x46, // name: "EF"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x2, 0x47, 0x48, // name: "GH"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x0, 0x0, 0x0}, // ThrottleTime
		proxylib.DROP, 4+42)
	s.checkAccessLogs(c, 0, 1)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithApiVersion(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: 3
			client_id: "ABC"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.PASS, 4+42)
	s.checkAccessLogs(c, 1, 0)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithApiVersionMismatch(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: 0
			client_id: "ABC"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data,
		// Error response:
		[]byte{0x0, 0x0, 0x0, 0x1c, // length
			0x0, 0x1, 0x0, 0x1, // Correlation ID (65537)
			0x0, 0x0, 0x0, 0x2, // 2 topics
			0x0, 0x2, 0x45, 0x46, // name: "EF"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x2, 0x47, 0x48, // name: "GH"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x0, 0x0, 0x0}, // ThrottleTime
		proxylib.DROP, 4+42)
	s.checkAccessLogs(c, 0, 1)
}

func (s *KafkaSuite) TestKafkaOnDataSimpleHeaderWithClientIDDeny(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		endpoint_ips: "1.1.1.1"
		endpoint_id: 2000
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1000
		    l7_proto: "kafka"
		    kafka_rules: <
		      kafka_rules: <
			api_version: -1
			topic: "EF"
			client_id: "ABCD"
		      >
		      kafka_rules: <
			api_version: -1
			topic: "GH"
		      >
		    >
		  >
		>
		`})

	data := hexData(c, testMessage1, testMessage2, testMessage3)

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "1.1.1.1")
	conn.CheckOnDataOK(c, false, false, &data,
		// Error response:
		[]byte{0x0, 0x0, 0x0, 0x1c, // length
			0x0, 0x1, 0x0, 0x1, // Correlation ID (65537)
			0x0, 0x0, 0x0, 0x2, // 2 topics
			0x0, 0x2, 0x45, 0x46, // name: "EF"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x2, 0x47, 0x48, // name: "GH"
			0x0, 0x0, 0x0, 0x0, // 0 partitions
			0x0, 0x0, 0x0, 0x0}, // ThrottleTime
		proxylib.DROP, 4+42)
	s.checkAccessLogs(c, 0, 1)
}

func (s *KafkaSuite) TestKafkaOnDataResponse(c *C) {
	data := [][]byte{
		{0x0, 0x0, 0x0, 0x1c}, // length
		{0x0, 0x1, 0x0, 0x1},  // Correlation ID (65537)
		{0x0, 0x0, 0x0, 0x2},  // 2 topics
		{0x0, 0x2, 0x45, 0x46, // name: "EF"
			0x0, 0x0, 0x0, 0x0}, // 0 partitions
		{0x0, 0x2, 0x47, 0x48, // name: "GH"
			0x0, 0x0, 0x0, 0x0}, // 0 partitions
		{0x0, 0x0, 0x0, 0x0}, // ThrottleTime
	}

	conn := s.ins.CheckNewConnectionOK(c, "kafka", true, 1000, 2000, "1.1.1.1:34567", "10.0.0.2:80", "")
	conn.CheckOnDataOK(c, true, false, &data, []byte{}, proxylib.PASS, 4+28)
	s.checkAccessLogs(c, 1, 0)
}
