// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graceful_termination

import (
	"os"
	"path"
	"testing"

	operatorOption "github.com/cilium/cilium/operator/option"
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/services/helpers"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("Services/GracefulTermination", testGracefulTermination)

}

func testGracefulTermination(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	abs := func(f string) string { return path.Join(cwd, "services", "graceful-termination", f) }

	modConfig := func(daemonCfg *agentOption.DaemonConfig, _ *operatorOption.OperatorConfig) {
		daemonCfg.EnableK8sTerminatingEndpoint = true
	}

	k8sVersions := controlplane.K8sVersions()
	// We only need to test the last k8s version
	test := suite.NewControlPlaneTest(t, "graceful-term-control-plane", k8sVersions[len(k8sVersions)-1])
	defer test.StopAgent()

	// Feed in initial state and start the agent.
	test.
		UpdateObjectsFromFile(abs("init.yaml")).
		SetupEnvironment(modConfig).
		StartAgent().

		// Step 1: Initial creation of the services and backends
		// lbmap1.golden: Shows graceful-term-svc service with an active backend
		UpdateObjectsFromFile(abs("state1.yaml")).
		Eventually(func() error { return helpers.ValidateLBMapGoldenFile(abs("lbmap1.golden"), test.Datapath) }).

		// Step 2: Pod is being deleted and endpoint is set to terminating state
		// lbmap2.golden: The backend state is 'terminating'
		UpdateObjectsFromFile(abs("state2.yaml")).
		Eventually(func() error { return helpers.ValidateLBMapGoldenFile(abs("lbmap2.golden"), test.Datapath) }).

		// Step 3: Endpoint has now been removed from the endpoint slice.
		// lbmap3.golden: The graceful-term-svc service no longer has any backeds
		UpdateObjectsFromFile(abs("state3.yaml")).
		Eventually(func() error { return helpers.ValidateLBMapGoldenFile(abs("lbmap3.golden"), test.Datapath) })
}
