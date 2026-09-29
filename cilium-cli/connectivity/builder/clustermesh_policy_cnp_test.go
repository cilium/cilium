// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"bytes"
	"context"
	"testing"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
)

func TestClusterMeshPolicyCNPTestsSkipWithoutMultiCluster(t *testing.T) {
	params := check.Parameters{
		FlowValidation: check.FlowValidationModeDisabled,
		TestNamespace:  "cilium-test-1",
	}
	var logs bytes.Buffer
	logger := check.NewConcurrentLogger(&logs)
	logger.Start()
	defer logger.Stop()

	ct, err := check.NewConnectivityTest(nil, params, nil, logger, nil)
	if err != nil {
		t.Fatalf("NewConnectivityTest() failed: %v", err)
	}
	ct.ClusterNameLocal = "local"
	ct.ClusterNameRemote = "local"

	templates, err := renderTemplates(ct.ClusterNameLocal, ct.ClusterNameRemote, params)
	if err != nil {
		t.Fatalf("renderTemplates() failed: %v", err)
	}

	builders := []testBuilder{
		clusterMeshPolicyCNPIngress{},
		clusterMeshPolicyCNPEgress{},
		clusterMeshPolicyCNPIngressL7{},
		clusterMeshPolicyCNPEgressL7{},
	}
	for _, builder := range builders {
		builder.build(ct, templates)
	}

	if err := ct.Run(context.Background()); err != nil {
		t.Fatalf("standalone connectivity run failed: %v", err)
	}
}
