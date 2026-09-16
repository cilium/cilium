// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
)

// This checks if the Gateway API v1 UDPRoute CRD is registered in the client scheme.
func HasInferencePoolSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(GatewayIEV1GVK("InferencePool"))
}
