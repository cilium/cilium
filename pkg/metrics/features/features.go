// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

func updateAgentConfigMetricOnStart(jg job.Group, params featuresParams, m featureMetrics) error {
	jg.Add(job.OneShot("update-config-metric", func(ctx context.Context, health cell.Health) error {
		// We depend on settings modified by the Daemon startup.
		// Once the Deamon is initialized this promise
		// is resolved and we are guaranteed to have the correct settings.
		health.OK("Waiting for agent config")
		agentConfig, err := params.ConfigPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to get agent config: %w", err)
		}
		m.update(&params, agentConfig, params.LBConfig)
		return nil
	}))

	return nil
}
