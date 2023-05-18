// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package revert

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
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
