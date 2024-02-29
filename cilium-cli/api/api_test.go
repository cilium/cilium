// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium-cli/k8s"
)

func TestNamespaceContextValues(t *testing.T) {
	ctx := context.Background()
	namespace := "mynamespace"
	ctx = SetNamespaceContextValue(ctx, namespace)
	result, ok := GetNamespaceContextValue(ctx)
	assert.True(t, ok)
	assert.Equal(t, namespace, result)
}

func TestK8sClientContextValues(t *testing.T) {
	ctx := context.Background()
	k8sClient, err := k8s.NewClient("", "", "")
	assert.NoError(t, err)
	ctx = SetK8sClientContextValue(ctx, k8sClient)
	result, ok := GetK8sClientContextValue(ctx)
	assert.True(t, ok)
	assert.Equal(t, k8sClient, result)
}
