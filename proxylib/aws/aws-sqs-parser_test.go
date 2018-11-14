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
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	// log.SetLevel(log.DebugLevel)

	TestingT(t)
}

type AWSSQSSuite struct {
	logServer *test.AccessLogServer
	ins       *proxylib.Instance
}

var _ = Suite(&AWSSQSSuite{})

// Set up access log server and Library instance for all the test cases
func (s *AWSSQSSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.ins = proxylib.NewInstance("node1", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.ins, Not(IsNil))
}

func (s *AWSSQSSuite) checkAccessLogs(c *C, expPasses, expDrops int) {
	passes, drops := s.logServer.Clear()
	c.Check(passes, Equals, expPasses, Commentf("Unxpected number of passed access log messages"))
	c.Check(drops, Equals, expDrops, Commentf("Unxpected number of passed access log messages"))
}

func (s *AWSSQSSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *AWSSQSSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

// according to the AWS docs, for GET requests at least, queue-name is in the URL.
func (s *AWSSQSSuite) TestBasicGetRequest(c *C) {
	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-sqs"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	// default: if no content-type or content-length is included, assume 0
	req1 := "GET /123456789012/MyQueue/?Action=SendMessage&MessageBody=This+is+a+test+message HTTP/1.0\r\n" +
		"\r\n"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

// based on using the AWS-CLI, which uses POST, it seems like the path used is "/" and QueueURL is always passed in as a parameter
func (s *AWSSQSSuite) TestBasicPostRequest(c *C) {
	// allow all rule
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-sqs"
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amazonaws.com%2F679388779924%2Fq1&Version=2012-11-05&MessageBody=hello1"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *AWSSQSSuite) TestBasicAllowByAction(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-sqs"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "action"
			  value: "SendMessage"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amazonaws.com%2F679388779924%2Fq1&Version=2012-11-05&MessageBody=hello1"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *AWSSQSSuite) TestBasicDenyByAction(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-sqs"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "action"
			  value: "ReceiveMessage"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amazonaws.com%2F679388779924%2Fq1&Version=2012-11-05&MessageBody=hello1"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(SQSAccessDeniedStr),
		proxylib.DROP, len(data[0]))
}

func (s *AWSSQSSuite) TestBasicAllowByQueue(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-sqs"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "queue_name"
			  value: "679388779924.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amazonaws.com%2F679388779924%2Fq1&Version=2012-11-05&MessageBody=hello1"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *AWSSQSSuite) TestBasicDenyByQueue(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-sqs"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "queue_name"
			  value: "999999.*"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amazonaws.com%2F679388779924%2Fq1&Version=2012-11-05&MessageBody=hello1"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(SQSAccessDeniedStr),
		proxylib.DROP, len(data[0]))
}

func (s *AWSSQSSuite) TestIncompleteRequestHeader(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 1)
}

func (s *AWSSQSSuite) TestIncompleteRequestBody(c *C) {
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amaz"
	data := [][]byte{[]byte(req1)}
	conn.CheckOnDataOK(c, false, false, &data, []byte{}, proxylib.MORE, 67) // 67 bytes missing
}

func (s *AWSSQSSuite) TestDoubleRequest(c *C) {
	s.ins.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    l7_proto: "aws-sqs"
		    l7_rules: <
		      l7_rules: <
			rule: <
			  key: "queue_name"
			  value: ".*/q1"
			>
		      >
		    >
		  >
		>
		`})
	conn := s.ins.CheckNewConnectionOK(c, "aws-sqs", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	req1 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amazonaws.com%2F679388779924%2Fq1&Version=2012-11-05&MessageBody=hello1"

	// changes queue name to 'q2'
	req2 := "POST / HTTP/1.1\r\n" +
		"Content-Length: 126\r\n" +
		"Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n" +
		"\r\n" +
		"Action=SendMessage&QueueUrl=http%3A%2F%2Fsqs.us-west-2.amazonaws.com%2F679388779924%2Fq2&Version=2012-11-05&MessageBody=hello1"
	data := [][]byte{[]byte(req1 + req2)}
	conn.CheckOnDataOK(c, false, false, &data, []byte(SQSAccessDeniedStr),
		proxylib.PASS, len(req1),
		proxylib.DROP, len(req2))
}
