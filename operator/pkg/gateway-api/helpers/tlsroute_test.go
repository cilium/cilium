// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestHasTLSRouteSupport(t *testing.T) {
	scheme1 := runtime.NewScheme()
	assert.False(t, HasTLSRouteSupport(scheme1), "Should be false when group is not registered")

	scheme2 := runtime.NewScheme()
	scheme2.AddKnownTypes(GatewayV1GVK("TCPRoute").GroupVersion(), &gatewayv1.TCPRoute{})
	assert.False(t, HasTLSRouteSupport(scheme2), "Should be false when group is registered but TLSRoute kind is not")

	scheme3 := runtime.NewScheme()
	err := gatewayv1.Install(scheme3)
	assert.NoError(t, err)
	assert.True(t, HasTLSRouteSupport(scheme3), "Should be true when TLSRoute kind is registered")
}
