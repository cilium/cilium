// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

func TestHasTLSRouteSupport(t *testing.T) {
	// Create a scheme without TLSRoute registered
	scheme := runtime.NewScheme()
	assert.False(t, HasTLSRouteSupport(scheme))

	// Register the TLSRoute group
	err := gatewayv1alpha2.AddToScheme(scheme)
	assert.NoError(t, err)
	assert.True(t, HasTLSRouteSupport(scheme))
}
