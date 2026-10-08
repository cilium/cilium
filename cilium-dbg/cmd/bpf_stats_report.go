// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/pkg/bpf/stats"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/hive"
)

var (
	sortField     string
	podFilters    []string
	deviceFilters []string
	jsonOutput    bool
)

var bpfStatsReportCmd = &cobra.Command{
	Use:          "report",
	Short:        "Display BPF runtime stats",
	Long:         `Display BPF runtime stats.`,
	SilenceUsage: true,
	Example: `  # Display all BPF runtime stats
  cilium-dbg bpf stats report

  # Filter by pod name "my-pod" in the "default" namespace
  cilium-dbg bpf stats report --pod=default/my-pod

  # Filter by device name "eth0"
  cilium-dbg bpf stats report --device=eth0

  # Sort by total runtime
  cilium-dbg bpf stats report --sort=total

  # Sort by number of runs
  cilium-dbg bpf stats report --sort=runs

  # Sort by average/total runtime or total runs
  cilium-dbg bpf stats report --sort=avg/total/runs`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := hive.DefaultShellConfig
		if err := cfg.Parse(cmd.Flags()); err != nil {
			return err
		}

		var shellArgs []string
		if sortField != "" {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", stats.SortFlagName, sortField))
		}
		for _, pod := range podFilters {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", stats.PodFlagName, pod))
		}
		for _, dev := range deviceFilters {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", stats.DeviceFlagName, dev))
		}

		if jsonOutput || command.OutputOption() {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s", stats.JSONFlag))
		}

		shellCmd := "bpf/stats/report"
		if len(shellArgs) > 0 {
			shellCmd = fmt.Sprintf("%s %s", shellCmd, strings.Join(shellArgs, " "))
		}

		err := shell.ShellExchange(cfg, os.Stdout, shellCmd)
		if err != nil {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	BPFStatsCmd.AddCommand(bpfStatsReportCmd)
	bpfStatsReportCmd.Flags().StringVar(&sortField, stats.SortFlagName, "avg", "Sort by average runtime (avg), total runtime (total), or number of runs (runs)")
	bpfStatsReportCmd.Flags().StringSliceVar(&podFilters, stats.PodFlagName, []string{}, "Filter by pod name(s)")
	bpfStatsReportCmd.Flags().StringSliceVar(&deviceFilters, stats.DeviceFlagName, []string{}, "Filter by device name(s) (e.g. host, eth0, cilium_wg0)")
	bpfStatsReportCmd.Flags().BoolVar(&jsonOutput, stats.JSONFlag, false, "Output report in JSON")
	command.AddOutputOption(bpfStatsReportCmd)
	hive.DefaultShellConfig.Flags(bpfStatsReportCmd.Flags())
}
