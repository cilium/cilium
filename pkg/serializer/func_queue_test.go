// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

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
