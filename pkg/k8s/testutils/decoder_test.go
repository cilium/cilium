// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func TestDecodeFile(t *testing.T) {
	// Slim CoreV1 objects can be decoded.
	obj, err := DecodeFile("testdata/service.yaml")
	require.NoError(t, err, "DecodeFile service.yaml")
	require.IsType(t, &slim_corev1.Service{}, obj)

	// Cilium objects can be decoded.
	obj, err = DecodeFile("testdata/ciliumnode.yaml")
	require.NoError(t, err, "DecodeFile ciliumnode.yaml")
	require.IsType(t, &cilium_v2.CiliumNode{}, obj)
}
