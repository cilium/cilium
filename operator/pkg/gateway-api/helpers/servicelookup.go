// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func GetBackendServiceName(namespace string, backendObjectReference gatewayv1.BackendObjectReference, resourceConfig ResourceConfig) (string, bool) {
	switch {
	case IsService(backendObjectReference):
		return string(backendObjectReference.Name), true

	case resourceConfig.IncludeServiceImports && IsServiceImport(backendObjectReference):
		return derivedName(types.NamespacedName{Name: string(backendObjectReference.Name), Namespace: namespace}), true

	case resourceConfig.IncludeInferencePools && IsInferencePool(backendObjectReference):
		return ShadowServiceName(string(backendObjectReference.Name)), true

	default:
		return "", false
	}
}

// derivedName derive the original name in the format "derived-$hash".
// This function was taken from the mcs-api repo: https://github.com/kubernetes-sigs/mcs-api/blob/4231f56e5ff985676b8ac99034b05609cf4a9e0d/pkg/controllers/common.go#L39
func derivedName(name types.NamespacedName) string {
	hash := sha256.New()
	hash.Write([]byte(name.String()))
	return "derived-" + strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(hash.Sum(nil)))[:10]
}
