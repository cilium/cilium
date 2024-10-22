// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dualstack

import (
	"os"
	"path"
	"testing"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/services/helpers"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("Services/DualStack", testDualStack)
}

func testDualStack(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	modConfig := func(cfg *option.DaemonConfig) {
		cfg.EnableIPv6 = true
		cfg.EnableNodePort = true
	}

	for _, version := range controlplane.K8sVersions() {
		abs := func(f string) string { return path.Join(cwd, "services", "dualstack", "v"+version, f) }

		t.Run("v"+version, func(t *testing.T) {
			test := suite.NewControlPlaneTest(t, "dual-stack-worker", version)

			// Feed in initial state and start the agent.
			test.
				UpdateObjectsFromFile(abs("init.yaml")).
				SetupEnvironment().
				StartAgent(modConfig).
				EnsureWatchers("endpointslices", "services").
				UpdateObjectsFromFile(abs("state1.yaml")).
				Eventually(func() error { return validate(abs("lbmap1.golden"), test) }).
				StopAgent().
				ClearEnvironment()
		})
	}
}

func validate(file string, test *suite.ControlPlaneTest) error {
	if err := helpers.ValidateLBMapGoldenFile(file, test.FakeLbMap); err != nil {
		return err
	}

	assert := helpers.NewLBMapAssert(test.FakeLbMap)

	// Verify that default/echo-dualstack service exists
	// for both NodePort and ClusterIP, and that it has backends
	// for udp:69, and tcp:80 for both IPv4 and IPv6.
	err := assert.ServicesExist(
		"default/echo-dualstack",
		[]lb.SVCType{lb.SVCTypeNodePort, lb.SVCTypeClusterIP},
		[]helpers.SVCL3Type{helpers.SVCIPv4, helpers.SVCIPv6},
		lb.UDP,
		69)
	if err != nil {
		return err
	}

	err = assert.ServicesExist(
		"default/echo-dualstack",
		[]lb.SVCType{lb.SVCTypeNodePort, lb.SVCTypeClusterIP},
		[]helpers.SVCL3Type{helpers.SVCIPv4, helpers.SVCIPv6},
		lb.TCP,
		80)
	if err != nil {
		return err
	}

	return nil
}
