// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"
	"fmt"
	"runtime/pprof"

	"github.com/cilium/cilium/pkg/hive/job"
)

func newAgentConfigMetricOnStart(params featuresParams, m featureMetrics) {
	jobGroup := params.JobRegistry.NewGroup(
		job.WithPprofLabels(pprof.Labels("cell", "features")),
	)

	jobGroup.Add(
		job.OneShot("update-config-metric", func(ctx context.Context) error {
			agentConfig, err := params.ConfigPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to get agent config: %w", err)
			}
			m.update(&params, agentConfig)
			return nil
		}),
	)

	params.Lifecycle.Append(jobGroup)
}
