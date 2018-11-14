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

package awsparsers

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
func DynamoDBTest(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type AWSDynamoDBSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&AWSDynamoDBSuite{})

// Set up access log server and Library instance for all the test cases
func (s *AWSDynamoDBSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *AWSDynamoDBSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *AWSDynamoDBSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *AWSDynamoDBSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

// according to the AWS docs, for GET requests at least, queue-name is in the URL.
func (s *AWSDynamoDBSuite) TestBasicGetItemRequest(c *C) {
	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp100"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-dynamodb"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-dynamodb", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp100")
	req1 := "POST / HTTP/1.1\r\n" +
		"Host: dynamodb.region.domain\r\n" +
		"Accept-Encoding: identity\r\n" +
		"Content-Length: 23\r\n" +
		"User-Agent: foo\r\n" +
		"Content-Type: application/x-amz-json-1.0\r\n" +
		"Authorization: AWS4-HMAC-SHA256 Credential=xxx, SignedHeaders=xxx, Signature=xxx\r\n" +
		"X-Amz-Date: xxx\r\n" +
		"X-Amz-Target: DynamoDB_20120810.GetItem\r\n" +
		"\r\n" +
		"{\"TableName\": \"Thread\"}"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}
