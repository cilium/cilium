// Copyright 2017 Authors of Cilium
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

package serializer

import (
	"errors"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type SerializerSuite struct{}

var _ = Suite(&SerializerSuite{})

func (s *SerializerSuite) TestFuncSerializer(c *C) {
	stopTest := make(chan struct{})
	nRetriesExecuted := 0
	nRetriesExpected := 3

	f := func() error {
		nRetriesExecuted++
		return errors.New("Failed")
	}

	wf := func(nRetries int) bool {
		if nRetries >= nRetriesExpected {
			close(stopTest)
			return false
		}
		return true
	}

	fs := NewFunctionQueue(1)

	fs.Enqueue(f, wf)

	select {
	case <-stopTest:
	case <-time.NewTimer(5 * time.Second).C:
		c.Fatalf("FuncSerializer failed to execute")
	}

	c.Assert(nRetriesExecuted, Equals, nRetriesExpected)
}
