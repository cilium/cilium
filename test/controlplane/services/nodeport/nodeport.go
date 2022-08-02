// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeport

import (
	"os"
	"path"
	"testing"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane/services/helpers"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("Services/NodePort", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}

		modConfig := func(c *option.DaemonConfig) { c.EnableNodePort = true }

		for _, version := range []string{"1.20", "1.22", "1.24"} {
			abs := func(f string) string { return path.Join(cwd, "services", "nodeport", "v"+version, f) }

			t.Run("v"+version, func(t *testing.T) {
				test := suite.NewControlPlaneTest(t, "nodeport-control-plane", version)

				// Feed in initial state and start the agent.
				test.
					UpdateObjectsFromFile(abs("init.yaml")).
					StartAgent(modConfig).
					UpdateObjectsFromFile(abs("state1.yaml")).
					Eventually(func() error { return helpers.ValidateLBMapGoldenFile(abs("lbmap1.golden"), test.Datapath) }).
					StopAgent()
			})
		}
	})
}
