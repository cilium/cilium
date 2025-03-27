// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/cilium-cli/clustermesh"
)

func TestClusterMeshDisconnectWithoutDestination(t *testing.T) {
	// Create clustermesh parameters without destination context
	params := clustermesh.Parameters{}

	// Create a K8sClusterMesh instance directly
	cm := clustermesh.NewK8sClusterMesh(nil, params)

	// Call DisconnectWithHelm and check the error
	err := cm.DisconnectWithHelm(context.Background())

	// Verify the error message
	assert.Equal(t, "no destination context specified, use --destination-context to specify which cluster to disconnect from", err.Error())
}
