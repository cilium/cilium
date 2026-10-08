// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestHasTCPRouteSupport(t *testing.T) {
	scheme1 := runtime.NewScheme()
	assert.False(t, HasTCPRouteSupport(scheme1), "Should be false when group is not registered")

	scheme2 := runtime.NewScheme()
	scheme2.AddKnownTypes(GatewayV1GVK("TLSRoute").GroupVersion(), &gatewayv1.TLSRoute{})
	assert.False(t, HasTCPRouteSupport(scheme2), "Should be false when group is registered but TCPRoute kind is not")

	scheme3 := runtime.NewScheme()
	err := gatewayv1.Install(scheme3)
	assert.NoError(t, err)
	assert.True(t, HasTCPRouteSupport(scheme3), "Should be true when TCPRoute kind is registered")
}
