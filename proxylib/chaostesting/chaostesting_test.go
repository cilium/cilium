// Copyright 2019 Authors of Cilium
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

package chaostesting

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/cilium/cilium/proxylib/accesslog"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	TestingT(t)
}

type ChaosTestingSuite struct {
	logServer        *test.AccessLogServer
	proxylibInstance *proxylib.Instance
}

var _ = Suite(&ChaosTestingSuite{})

func (s *ChaosTestingSuite) SetUpSuite(c *C) {
	s.logServer = test.StartAccessLogServer("access_log.sock", 10)
	c.Assert(s.logServer, Not(IsNil))
	s.proxylibInstance = proxylib.NewInstance("node", accesslog.NewClient(s.logServer.Path))
	c.Assert(s.proxylibInstance, Not(IsNil))
}

func (s *ChaosTestingSuite) TearDownTest(c *C) {
	s.logServer.Clear()
}

func (s *ChaosTestingSuite) TearDownSuite(c *C) {
	s.logServer.Close()
}

func newHTTPRequest(c *C) (*http.Request, []byte) {
	bodyReader := strings.NewReader("Build a wall?")
	httpRequest, err := http.NewRequest("GET", "https://foo.com", bodyReader)
	c.Assert(err, IsNil)

	buf := new(bytes.Buffer)
	httpRequest.Write(buf)

	return httpRequest, buf.Bytes()
}

func newHTTPResponse(c *C, req *http.Request) *http.Response {
	responseBody := "No"
	httpResponse := &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(bytes.NewBufferString(responseBody)),
		ContentLength: int64(len(responseBody)),
		Request:       req,
		Header:        make(http.Header, 0),
	}
	return httpResponse
}

func newHTTPResponseWithBytes(c *C, req *http.Request) (*http.Response, []byte) {
	httpResponse := newHTTPResponse(c, req)
	buf := new(bytes.Buffer)
	httpResponse.Write(buf)
	return httpResponse, buf.Bytes()
}

func (s *ChaosTestingSuite) TestDelay(c *C) {
	s.proxylibInstance.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    l7_proto: "chaos"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "method"
		          value: "GET"
		        >
		        rule: <
		          key: "delay-request"
		          value: "1s"
		        >
		      >
		    >
		  >
		>
		`})
	conn := s.proxylibInstance.CheckNewConnectionOK(c, "chaos", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")

	_, reqBytes := newHTTPRequest(c)

	bodyReader := strings.NewReader("Build a wall?")
	modifiedHTTPRequest, err := http.NewRequest("GET", "https://foo.com", bodyReader)
	c.Assert(err, IsNil)

	modifiedHTTPRequest.Header.Add("X-Cilium-Delay", "Delayed request by 1s")
	buf := new(bytes.Buffer)
	modifiedHTTPRequest.Write(buf)

	data := [][]byte{reqBytes}
	conn.CheckOnDataOK(c, false, false, &data, buf.Bytes(),
		proxylib.INJECT, len(buf.Bytes()))

	_, respBytes := newHTTPResponseWithBytes(c, modifiedHTTPRequest)
	data = [][]byte{respBytes}
	conn.CheckOnDataOK(c, true, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *ChaosTestingSuite) TestSingleReadSingleWrite(c *C) {
	s.proxylibInstance.CheckInsertPolicyText(c, "1", []string{})
	conn := s.proxylibInstance.CheckNewConnectionOK(c, "chaos", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")

	httpRequest, reqBytes := newHTTPRequest(c)
	data := [][]byte{reqBytes}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))

	_, respBytes := newHTTPResponseWithBytes(c, httpRequest)
	data = [][]byte{respBytes}
	conn.CheckOnDataOK(c, true, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *ChaosTestingSuite) TestSplitSlices(c *C) {
	s.proxylibInstance.CheckInsertPolicyText(c, "1", []string{})
	conn := s.proxylibInstance.CheckNewConnectionOK(c, "chaos", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")

	httpRequest, reqBytes := newHTTPRequest(c)

	data := [][]byte{
		reqBytes[0:10],
		reqBytes[10:20],
		reqBytes[20:],
	}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(reqBytes))

	_, respBytes := newHTTPResponseWithBytes(c, httpRequest)
	data = [][]byte{respBytes}
	conn.CheckOnDataOK(c, true, false, &data, []byte{},
		proxylib.PASS, len(respBytes))
}

func (s *ChaosTestingSuite) TestSplitRead(c *C) {
	s.proxylibInstance.CheckInsertPolicyText(c, "1", []string{})
	conn := s.proxylibInstance.CheckNewConnectionOK(c, "chaos", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")

	httpRequest, reqBytes := newHTTPRequest(c)

	data1 := [][]byte{
		reqBytes[0:10],
	}
	data2 := [][]byte{
		reqBytes[0:10],
		reqBytes[10:20],
		reqBytes[20:],
	}
	conn.CheckOnDataOK(c, false, false, &data1, []byte{},
		proxylib.MORE, 1)
	conn.CheckOnDataOK(c, false, false, &data2, []byte{},
		proxylib.PASS, len(reqBytes))

	_, respBytes := newHTTPResponseWithBytes(c, httpRequest)
	data := [][]byte{respBytes}
	conn.CheckOnDataOK(c, true, false, &data, []byte{},
		proxylib.PASS, len(data[0]))
}

func (s *ChaosTestingSuite) TestRewriteStatusCode(c *C) {
	s.proxylibInstance.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    l7_proto: "chaos"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "rewrite-status"
		          value: "403 FORBIDDEN"
		        >
		      >
		    >
		  >
		>
		`})
	conn := s.proxylibInstance.CheckNewConnectionOK(c, "chaos", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")

	httpRequest, reqBytes := newHTTPRequest(c)
	data := [][]byte{reqBytes}
	conn.CheckOnDataOK(c, false, false, &data, []byte{},
		proxylib.PASS, len(data[0]))

	_, respBytes := newHTTPResponseWithBytes(c, httpRequest)

	modifiedResp := newHTTPResponse(c, httpRequest)
	modifiedResp.Status = "403 FORBIDDEN"
	modifiedResp.StatusCode = 403
	modifiedResp.Header.Add("X-Cilium-Modified-Status-Code", "The status code has been modified by Cilium")
	buf := new(bytes.Buffer)
	modifiedResp.Write(buf)

	data = [][]byte{respBytes}
	conn.CheckOnDataOK(c, true, false, &data, buf.Bytes(),
		proxylib.INJECT, len(buf.Bytes()))
}

func (s *ChaosTestingSuite) TestLargeRequest(c *C) {
	s.proxylibInstance.CheckInsertPolicyText(c, "1", []string{`
		name: "cp1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    l7_proto: "chaos"
		    l7_rules: <
		      l7_rules: <
		        rule: <
		          key: "rewrite-status"
		          value: "403 FORBIDDEN"
		        >
		      >
		    >
		  >
		>
		`})
	conn := s.proxylibInstance.CheckNewConnectionOK(c, "chaos", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")

	payload := make([]byte, 1024*4)
	for i := 0; i < len(payload); i++ {
		payload[i] = 'A'
	}

	bodyReader := bytes.NewReader(payload)
	httpRequest, err := http.NewRequest("GET", "https://foo.com", bodyReader)
	c.Assert(err, IsNil)

	buf := new(bytes.Buffer)
	httpRequest.Write(buf)
	reqBytes := buf.Bytes()

	data1 := [][]byte{
		reqBytes[0 : 2*1024],
	}
	data2 := [][]byte{
		reqBytes[0 : 2*1024],
		reqBytes[2*1024 : 3*1024],
	}
	data3 := [][]byte{
		reqBytes[0 : 2*1024],
		reqBytes[2*1024 : 3*1024],
		reqBytes[3*1024:],
	}

	conn.CheckOnDataOK(c, false, false, &data1, []byte{},
		proxylib.MORE, 1)
	conn.CheckOnDataOK(c, false, false, &data2, []byte{},
		proxylib.MORE, 1)
	conn.CheckOnDataOK(c, false, false, &data3, []byte{}, proxylib.PASS, len(reqBytes))

	httpResponse := &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(bytes.NewBuffer(payload)),
		ContentLength: int64(len(payload)),
		Request:       httpRequest,
		Header:        make(http.Header, 0),
	}

	buf = new(bytes.Buffer)
	httpResponse.Write(buf)
	respBytes := buf.Bytes()

	data1 = [][]byte{
		respBytes[0 : 2*1024],
	}
	data2 = [][]byte{
		respBytes[0 : 2*1024],
		respBytes[2*1024 : 3*1024],
	}
	data3 = [][]byte{
		respBytes[0 : 2*1024],
		respBytes[2*1024 : 3*1024],
		respBytes[3*1024:],
	}

	conn.CheckOnDataOK(c, true, false, &data1, []byte{},
		proxylib.MORE, 1)
	conn.CheckOnDataOK(c, true, false, &data2, []byte{},
		proxylib.MORE, 1)

	modifiedHTTPResponse := httpResponse
	modifiedHTTPResponse.Status = "403 FORBIDDEN"
	modifiedHTTPResponse.StatusCode = 403
	modifiedHTTPResponse.Header.Add("X-Cilium-Modified-Status-Code", "The status code has been modified by Cilium")
	modifiedHTTPResponse.Body = ioutil.NopCloser(bytes.NewBuffer(payload))
	modifiedBuf := new(bytes.Buffer)
	modifiedHTTPResponse.Write(modifiedBuf)
	modifiedBytes := modifiedBuf.Bytes()

	conn.CheckOnDataOK(c, true, false, &data3, modifiedBytes[0:1024], proxylib.INJECT, 1024)
	conn.CheckOnDataOK(c, true, false, &data3, modifiedBytes[1024:2048], proxylib.INJECT, 1024)
	conn.CheckOnDataOK(c, true, false, &data3, modifiedBytes[2048:3072], proxylib.INJECT, 1024)
	conn.CheckOnDataOK(c, true, false, &data3, modifiedBytes[3072:4096], proxylib.INJECT, 1024)
	conn.CheckOnDataOK(c, true, false, &data3, modifiedBytes[4096:], proxylib.INJECT, len(modifiedBuf.Bytes())-(4*1024))
}

func (s *ChaosTestingSuite) TestMultiRequest(c *C) {
	//	s.proxylibInstance.CheckInsertPolicyText(c, "1", []string{})
	//	conn := s.proxylibInstance.CheckNewConnectionOK(c, "chaos", true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "cp1")
	//
	//	httpRequest, reqBytes := newHTTPRequest(c)
	//
	//	data1 := [][]byte{
	//		reqBytes[0:10],
	//	}
	//	data2 := [][]byte{
	//		reqBytes[0:10],
	//		reqBytes[10:20],
	//		reqBytes[20:],
	//	}
	//	conn.CheckOnDataOK(c, false, false, &data1, []byte{},
	//		proxylib.MORE, 1)
	//	conn.CheckOnDataOK(c, false, false, &data2, reqBytes,
	//		proxylib.INJECT, len(reqBytes))
	//
	//	_, respBytes := newHTTPResponseWithBytes(c, httpRequest)
	//	data := [][]byte{respBytes}
	//	conn.CheckOnDataOK(c, true, false, &data, respBytes,
	//		proxylib.INJECT, len(data[0]))
	//
	//	conn.CheckOnDataOK(c, false, false, &data1, []byte{},
	//		proxylib.MORE, 1)
	//	conn.CheckOnDataOK(c, false, false, &data2, reqBytes,
	//		proxylib.INJECT, len(reqBytes))
	//
	//	conn.CheckOnDataOK(c, true, false, &data, respBytes,
	//		proxylib.INJECT, len(data[0]))
}

func (s *ChaosTestingSuite) TestEqualBuffer(c *C) {
	d := bytes.NewBufferString("aaaabbbb")
	d1 := [][]byte{
		d.Bytes()[0:4],
		d.Bytes()[4:],
	}

	c.Assert(equalBuffer(d, d1), Equals, true)
}
