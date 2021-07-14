// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// MetricsCmd represents the metrics command for the operator.
var MetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Access metric status of the operator",
}
