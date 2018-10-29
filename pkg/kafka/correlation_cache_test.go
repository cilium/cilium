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

package kafka

import (
	"time"

	. "gopkg.in/check.v1"
)

var (
	request1 = &RequestMessage{rawMsg: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}}
	request2 = &RequestMessage{rawMsg: []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}}
)

func createResponse(req *RequestMessage) *ResponseMessage {
	res := &ResponseMessage{rawMsg: req.rawMsg}
	res.SetCorrelationID(req.GetCorrelationID())
	return res
}

func (k *kafkaTestSuite) TestCorrelation(c *C) {
	cc := NewCorrelationCache()

	req1FinishCalled, req2FinishCalled := false, false

	// save the original correlation ID for later checking
	origCorrelationID := request1.GetCorrelationID()

	cc.HandleRequest(request1, func(req *RequestMessage) { req1FinishCalled = true })

	// Verify that the correlation ID has been rewritten to the next
	// sequence number (1)
	c.Assert(request1.GetCorrelationID(), Equals, CorrelationID(1))

	// Successful correlation will remove the request from the cache so
	// subsequent correlation will return nil
	response1 := createResponse(request1)
	c.Assert(cc.CorrelateResponse(response1), Equals, request1)
	c.Assert(cc.CorrelateResponse(response1), IsNil)

	// Verify that the correlation id in the response has been restored to
	// the original value found in the request
	c.Assert(response1.GetCorrelationID(), Equals, origCorrelationID)

	cc.HandleRequest(request2, nil)

	// Verify that the correlation ID has been rewritten to the next
	// sequence number (2)
	c.Assert(request2.GetCorrelationID(), Equals, CorrelationID(2))

	response2 := createResponse(request2)
	c.Assert(cc.CorrelateResponse(response2), Equals, request2)
	c.Assert(cc.CorrelateResponse(response2), IsNil)

	// Check that only finish function of request was called as request2
	// did not have a finish function attached
	c.Assert(req1FinishCalled, Equals, true)
	c.Assert(req2FinishCalled, Equals, false)

	cc.DeleteCache()
}

func (k *kafkaTestSuite) TestCorrelationGC(c *C) {
	// reduce the lifetime of a request in the cache to 200 millisecond
	RequestLifetime = 200 * time.Millisecond

	cc := NewCorrelationCache()

	// sleep into half the request lifetime interval
	time.Sleep(100 * time.Millisecond)

	// Let initial GC run complete
	for cc.numGcRuns < 1 {
		time.Sleep(1 * time.Millisecond)
	}

	cc.HandleRequest(request1, nil)

	// Let another GC run pass
	for cc.numGcRuns < 2 {
		time.Sleep(1 * time.Millisecond)
	}

	// request1 should not have been expired yet
	response1 := createResponse(request1)
	c.Assert(cc.correlate(response1.GetCorrelationID()), Not(IsNil))

	// wait for the garbage collector to expire the request
	for cc.numExpired == 0 {
		time.Sleep(1 * time.Millisecond)
	}

	// Garbage collector must have removed the request from the cache
	c.Assert(cc.CorrelateResponse(response1), IsNil)
	response2 := createResponse(request2)
	c.Assert(cc.CorrelateResponse(response2), IsNil)

	cc.DeleteCache()
}
