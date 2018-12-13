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

package revert

import (
	"errors"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type RevertTestSuite struct{}

var _ = Suite(&RevertTestSuite{})

func (s *RevertTestSuite) TestRevertStack(c *C) {
	expectedContent := []string{"lmao", "ayy", "bar", "foo"}
	content := make([]string, 0, 4)
	rStack := RevertStack{}

	rStack.Push(func() error {
		content = append(content, "foo")
		return nil
	})
	rStack.Push(func() error {
		content = append(content, "bar")
		return nil
	})
	rStack.Push(func() error {
		content = append(content, "ayy")
		return nil
	})
	rStack.Push(func() error {
		content = append(content, "lmao")
		return nil
	})

	err := rStack.Revert()
	c.Assert(err, IsNil)

	c.Assert(content, checker.DeepEquals, expectedContent)
}

func (s *RevertTestSuite) TestRevertStackError(c *C) {
	var firstFuncCalled, secondFuncCalled, thirdFuncCalled bool
	rStack := RevertStack{}

	rStack.Push(func() error {
		firstFuncCalled = true
		return nil
	})
	rStack.Push(func() error {
		secondFuncCalled = true
		return errors.New("2nd function failed")
	})
	rStack.Push(func() error {
		thirdFuncCalled = true
		return nil
	})

	err := rStack.Revert()
	c.Assert(err, ErrorMatches, "failed to execute revert function; skipping 1 revert functions: 2nd function failed")

	c.Assert(firstFuncCalled, Equals, false)
	c.Assert(secondFuncCalled, Equals, true)
	c.Assert(thirdFuncCalled, Equals, true)
}
