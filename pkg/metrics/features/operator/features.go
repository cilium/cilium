// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

func updateOperatorConfigMetricOnStart(jg job.Group, params featuresParams, m featureMetrics) error {
	jg.Add(job.OneShot("update-config-metric", func(ctx context.Context, health cell.Health) error {
		health.OK("Updating metrics based on OperatorConfig")
		m.update(&params, params.OperatorConfig)
		return nil
	}))

	return nil
}
