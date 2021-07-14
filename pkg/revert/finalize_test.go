// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

// +build !privileged_tests

package revert

import (
	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

func (s *RevertTestSuite) TestFinalizeList(c *C) {
	expectedContent := []string{"foo", "bar", "ayy", "lmao"}
	content := make([]string, 0, 4)
	fList := FinalizeList{}

	fList.Append(func() {
		content = append(content, "foo")
	})
	fList.Append(func() {
		content = append(content, "bar")
	})
	fList.Append(func() {
		content = append(content, "ayy")
	})
	fList.Append(func() {
		content = append(content, "lmao")
	})
	fList.Finalize()

	c.Assert(content, checker.DeepEquals, expectedContent)
}
