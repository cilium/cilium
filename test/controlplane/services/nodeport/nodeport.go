// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeport

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/fake"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
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
					Eventually(func() error { return validate(test, abs("lbmap1.golden")) }).
					StopAgent()
			})
		}
	})
}

func validate(test *suite.ControlPlaneTest, goldenFile string) error {
	if err := helpers.ValidateLBMapGoldenFile(goldenFile, test.Datapath); err != nil {
		return err
	}
	if err := validateExternalTrafficPolicyLocal(test.Datapath); err != nil {
		return err
	}
	return nil
}

func validateExternalTrafficPolicyLocal(dp *fake.FakeDatapath) error {
	lbmap := dp.LBMockMap()
	lbmap.Lock()
	defer lbmap.Unlock()

	// Collect all echo-local services with internal ("local") scope.
	localServices := []*lb.SVC{}
	for _, svc := range dp.LBMockMap().ServiceByID {
		if svc.Name.Name == "echo-local" && svc.Frontend.Scope == lb.ScopeInternal {
			localServices = append(localServices, svc)
		}
	}

	expectedFrontendIPs := map[string]bool{}
	for _, ip := range dp.LocalNodeAddressing().IPv4().LoadBalancerNodeAddresses() {
		expectedFrontendIPs[ip.String()] = true
	}

	// Check that all expected service entries exist with the expected frontends.
	for _, svc := range localServices {
		ip := svc.Frontend.IP.String()
		if _, ok := expectedFrontendIPs[ip]; !ok {
			return fmt.Errorf("unexpected frontend IP %q for service %s, expected one of %v", ip, svc.Name, expectedFrontendIPs)
		}
		delete(expectedFrontendIPs, ip)
		if len(svc.Backends) != 1 {
			return fmt.Errorf("missing backend for %s, expected 1, got %d", svc.Name, len(svc.Backends))
		}
	}
	if len(expectedFrontendIPs) > 0 {
		return fmt.Errorf("missing services for frontends: %v", expectedFrontendIPs)
	}

	return nil
}
