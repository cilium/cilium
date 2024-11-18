// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
)

func Test_getNodeImage(t *testing.T) {
	tests := []struct {
		nodes    []corev1.Node
		expected string
		isErr    bool
	}{
		{
			isErr: true,
		},
		{
			nodes: []corev1.Node{
				createTestNode("Amazon Linux 2"),
			},
			expected: AwsNodeImageFamilyAmazonLinux2,
		},
		{
			nodes: []corev1.Node{
				createTestNode("Amazon Linux 2023.6.123"),
				createTestNode("Amazon Linux 2023.6.789"),
			},
			expected: AwsNodeImageFamilyAmazonLinux2023,
		},
		{
			nodes: []corev1.Node{
				createTestNode("Amazon Ubuntu Linux"),
			},
			expected: AwsNodeImageFamilyUbuntu,
		},
		{
			nodes: []corev1.Node{
				createTestNode("Amazon Windows Linux"),
			},
			expected: AwsNodeImageFamilyWindows,
		},
		{
			nodes: []corev1.Node{
				createTestNode("Amazon Bottlerocket Linux"),
			},
			expected: AwsNodeImageFamilyBottlerocket,
		},
		{
			nodes: []corev1.Node{
				createTestNode("Amazon Custom Linux"),
			},
			expected: AwsNodeImageFamilyCustom,
		},
		{
			nodes: []corev1.Node{
				createTestNode("Amazon Linux 2"),
				createTestNode("Amazon Linux 2023.6.20241031"),
			},
			isErr: true,
		},
	}

	for _, tt := range tests {
		actual, err := getNodeImage(tt.nodes)

		if tt.isErr {
			assert.Error(t, err)
			continue
		}

		assert.NoError(t, err)
		assert.Equal(t, tt.expected, actual)
	}
}

func createTestNode(osImage string) corev1.Node {
	return corev1.Node{
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				OSImage: osImage,
			},
		},
	}
}
