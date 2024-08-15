// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeport

import (
	"fmt"
	"net"
	"os"
	"path"
	"testing"

	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/services/helpers"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("Services/NodePort", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}

		modConfig := func(cfg *agentOption.DaemonConfig) {
			cfg.EnableNodePort = true
		}

		for _, version := range controlplane.K8sVersions() {
			abs := func(f string) string { return path.Join(cwd, "services", "nodeport", "v"+version, f) }

			// Run the test from each nodes perspective.
			for _, nodeName := range []string{"nodeport-control-plane", "nodeport-worker", "nodeport-worker2"} {
				t.Run("v"+version+"/"+nodeName, func(t *testing.T) {
					test := suite.NewControlPlaneTest(t, nodeName, version)

					// Feed in initial state and start the agent.
					test.
						UpdateObjectsFromFile(abs("init.yaml")).
						SetupEnvironment().
						StartAgent(modConfig).
						EnsureWatchers("endpointslices", "pods", "services").
						UpdateObjectsFromFile(abs("state1.yaml")).
						Eventually(func() error { return validate(test, abs("lbmap1_"+nodeName+".golden")) }).
						StopAgent().
						ClearEnvironment()
				})
			}
		}
	})
}

func validate(test *suite.ControlPlaneTest, goldenFile string) error {
	if err := helpers.ValidateLBMapGoldenFile(goldenFile, test.FakeLbMap); err != nil {
		return err
	}
	if err := validateExternalTrafficPolicyLocal(test); err != nil {
		return err
	}
	return nil
}

func validateExternalTrafficPolicyLocal(test *suite.ControlPlaneTest) error {
	test.FakeLbMap.Lock()
	defer test.FakeLbMap.Unlock()

	// Collect all echo-local services with internal ("local") scope.
	localServices := []*lb.SVC{}
	for _, svc := range test.FakeLbMap.ServiceByID {
		if svc.Name.Name == "echo-local" && svc.Frontend.Scope == lb.ScopeInternal {
			localServices = append(localServices, svc)
		}
	}

	expectedFrontendIPs := map[string]bool{}

	db, nodeAddrs := test.AgentDB()
	iter := nodeAddrs.List(db.ReadTxn(), datapathTables.NodeAddressNodePortIndex.Query(true))
	for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
		if addr.NodePort && addr.Addr.Is4() {
			expectedFrontendIPs[addr.Addr.String()] = true
		}
	}
	expectedFrontendIPs[net.IPv4zero.String()] = true

	// Check that all expected service entries exist with the expected frontends.
	for _, svc := range localServices {
		ip := svc.Frontend.AddrCluster.String()
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
