// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package revert

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFinalizeList(t *testing.T) {
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

	require.Equal(t, expectedContent, content)
}
