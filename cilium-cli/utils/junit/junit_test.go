// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package junit

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJunitFileName(t *testing.T) {
	testCases := []struct {
		name      string
		namespace string
		junitFile string
		expected  string
	}{
		{
			name:      "no junit report",
			namespace: "cilium-test",
			junitFile: "",
			expected:  "",
		},
		{
			name:      "junit report contains only file",
			namespace: "cilium-test",
			junitFile: "junit.xml",
			expected:  "cilium-test-junit.xml",
		},
		{
			name:      "junit report contains folder and file",
			namespace: "cilium-test",
			junitFile: "folder1" + string(os.PathSeparator) + "junit.xml",
			expected:  "folder1" + string(os.PathSeparator) + "cilium-test-junit.xml",
		},
		{
			name:      "junit report contains folders and file",
			namespace: "cilium-test",
			junitFile: "folder1" + string(os.PathSeparator) + "folder2" + string(os.PathSeparator) + "junit.xml",
			expected:  "folder1" + string(os.PathSeparator) + "folder2" + string(os.PathSeparator) + "cilium-test-junit.xml",
		},
		{
			name:      "junit report is absolute path",
			namespace: "cilium-test",
			junitFile: string(os.PathSeparator) + "folder1" + string(os.PathSeparator) + "folder2" + string(os.PathSeparator) + "junit.xml",
			expected:  string(os.PathSeparator) + "folder1" + string(os.PathSeparator) + "folder2" + string(os.PathSeparator) + "cilium-test-junit.xml",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			actual := NamespacedFileName(tt.namespace, tt.junitFile)

			require.Equal(t, tt.expected, actual)
		})
	}
}
