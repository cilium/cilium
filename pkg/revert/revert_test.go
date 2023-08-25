// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package revert

import (
	"errors"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
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
