// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

// WithCleanFqdnCache attaches a per-scenario setup callback to the test
// which cleans FQDN cache.
func (t *Test) WithCleanFqdnCache() *Test {
	t.WithScenarioSetupFunc(cleanFqdnCache)
	return t
}

// CleanFqdnCache cleans FQDN cache of the given node via its agent pod.
// The function signature matches SetupFunc.
func cleanFqdnCache(ctx context.Context, t *Test, ct *ConnectivityTest, s Scenario) error {
	for _, cp := range ct.ciliumPods {
		if err := cleanFqdnCacheOnAgent(ctx, ct, cp); err != nil {
			return err
		}
	}

	return nil
}

func cleanFqdnCacheOnAgent(ctx context.Context, log Logger, agent Pod) error {
	log.Debugf("[%s] Cleaning FQDN cache on %s...",
		agent.K8sClient.ClusterName(), agent.Name())

	ctx, cancel := context.WithTimeout(ctx, ShortTimeout)
	defer cancel()

	if _, err := agent.K8sClient.ExecInPod(ctx, agent.Namespace(), agent.NameWithoutNamespace(),
		defaults.AgentContainerName, []string{"cilium", "fqdn", "cache", "clean", "-f"}); err == nil {
		return nil
	} else {
		log.Debugf("[%s] Error cleaning FQDN cache: %s", agent.K8sClient.ClusterName(), err)
		return fmt.Errorf("failed to clean fqdn cache on %s: %w", agent.Name(), err)
	}
}
