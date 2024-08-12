// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hostport

import (
	"os"
	"path"
	"testing"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/services/helpers"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("Pod/HostPort", testHostPort)
}

func testHostPort(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	abs := func(f string) string { return path.Join(cwd, "pod", "hostport", f) }

	k8sVersions := controlplane.K8sVersions()
	// We only need to test the last k8s version
	test := suite.NewControlPlaneTest(t, "hostport-control-plane", k8sVersions[len(k8sVersions)-1])
	defer test.StopAgent()

	// Feed in initial state and start the agent.
	test.
		UpdateObjectsFromFile(abs("init.yaml")).
		SetupEnvironment().
		StartAgent(func(_ *option.DaemonConfig) {}).
		EnsureWatchers("pods").

		// Step 1: Create the first hostport pod.
		// lbmap1.golden: Hostport service exists in the Datapath with hostport-1 pod as backend.
		UpdateObjectsFromFile(abs("state1.yaml")).
		Eventually(func() error { return helpers.ValidateLBMapGoldenFile(abs("lbmap1.golden"), test.FakeLbMap) }).

		// Step 2: Mark the first pod as "completed", and create a second hostport pod using the same port
		// lbmap2.golden: Hostport service exists in the Datapath with hostport-2 pod as backend.
		UpdateObjectsFromFile(abs("state2.yaml")).
		Eventually(func() error { return helpers.ValidateLBMapGoldenFile(abs("lbmap2.golden"), test.FakeLbMap) }).

		// Step 3: Delete the completed pod, and verify that the hostport service doesn't get deleted.
		// lbmap3.golden: Hostport service still exists in the Datapath, with hostport-2 pod as backend.
		UpdateObjectsFromFile(abs("state3.yaml")).
		Eventually(func() error { return helpers.ValidateLBMapGoldenFile(abs("lbmap3.golden"), test.FakeLbMap) })
}
