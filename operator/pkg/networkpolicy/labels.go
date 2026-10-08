// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The networkpolicy package performs basic policy validation and updates
// the policy's Status field as relevant.

package networkpolicy

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/option"
)

type labelPrefixParams struct {
	cell.In

	DaemonCfg *option.DaemonConfig
	Logger    *slog.Logger
}

func registerLabelPrefixConfig(p labelPrefixParams) error {
	if err := labelsfilter.ParseLabelPrefixCfg(p.Logger, p.DaemonCfg.Labels, p.DaemonCfg.NodeLabels, p.DaemonCfg.LabelPrefixFile); err != nil {
		return fmt.Errorf("unable to parse label prefix configuration: %w", err)
	}
	return nil
}
