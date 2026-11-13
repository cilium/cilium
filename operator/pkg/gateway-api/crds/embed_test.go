// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crds

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TestStandardMatchesGoMod ensures that the embedded CRDs are kept in sync
// with the version of sigs.k8s.io/gateway-api used to build Cilium.
// Run `make manifests` to update them.
func TestStandardMatchesGoMod(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	require.True(t, ok, "build info not available")

	var moduleVersion string
	for _, dep := range info.Deps {
		if dep.Path == "sigs.k8s.io/gateway-api" {
			moduleVersion = dep.Version
			if dep.Replace != nil {
				moduleVersion = dep.Replace.Version
			}
		}
	}
	require.NotEmpty(t, moduleVersion, "sigs.k8s.io/gateway-api not found in build info")

	crds, err := Standard()
	require.NoError(t, err)
	require.NotEmpty(t, crds)

	for _, crd := range crds {
		require.Equal(t, gatewayv1.GroupName, crd.Spec.Group, crd.Name)
		require.Equal(t, ChannelStandard, crd.Annotations[ChannelAnnotation], crd.Name)
		require.Equal(t, moduleVersion, crd.Annotations[BundleVersionAnnotation],
			"%s is out of sync with go.mod, please run 'make manifests'", crd.Name)
	}
}
