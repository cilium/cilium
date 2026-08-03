// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	statstypes "github.com/cilium/cilium/pkg/bpf/stats/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	SortFlagName   = "sort"
	PodFlagName    = "pod"
	DeviceFlagName = "device"
	JSONFlag       = "json"
)

type bpfProgramStats struct {
	ProgramID    ebpf.ProgramID `json:"program_id,omitempty"`
	ProgramName  string         `json:"program_name"`
	ProgramType  string         `json:"program_type"`
	IfaceName    string         `json:"iface_name,omitempty"`
	PodNamespace string         `json:"pod_namespace,omitempty"`
	PodName      string         `json:"pod_name,omitempty"`
	TotalRuns    uint64         `json:"total_runs"`
	TotalRuntime time.Duration  `json:"total_runtime"`
	AvgRuntimeNS time.Duration  `json:"avg_runtime_ns"`
}

func reportCommand(status bpfStatsStatus, statsCollector statstypes.ProgStatsCollector) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Display BPF runtime stats",
			Flags: func(fs *pflag.FlagSet) {
				fs.String(SortFlagName, "avg", "Sort by average runtime (avg), total runtime (total), or number of runs (runs)")
				fs.StringSlice(PodFlagName, nil, "Filter by pod name(s)")
				fs.StringSlice(DeviceFlagName, nil, "Filter by device name(s)")
				fs.Bool(JSONFlag, false, "Output report in JSON")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if !status.Enabled() {
				return nil, fmt.Errorf("BPF stats are not enabled (enable-bpf-stats is false)")
			}

			sortField, err := s.Flags.GetString(SortFlagName)
			if err != nil {
				return nil, err
			}
			podFilters, err := s.Flags.GetStringSlice(PodFlagName)
			if err != nil {
				return nil, err
			}
			pods, err := parseNamespacedNames(podFilters)
			if err != nil {
				return nil, err
			}
			devices, err := s.Flags.GetStringSlice(DeviceFlagName)
			if err != nil {
				return nil, err
			}
			jsonOutput, err := s.Flags.GetBool(JSONFlag)
			if err != nil {
				return nil, err
			}

			if len(pods) == 0 {
				pods = nil
			}
			if len(devices) == 0 {
				devices = nil
			}

			stats, err := statsCollector.CollectProgramStats(pods, devices)
			if err != nil {
				return nil, fmt.Errorf("querying program stats: %w", err)
			}

			cmp, err := getCompareFunc(sortField, stats)
			if err != nil {
				return nil, err
			}

			sort.Slice(stats, cmp)

			if err := displayProgramStats(s.LogWriter(), stats, jsonOutput); err != nil {
				return nil, fmt.Errorf("displaying program stats: %w", err)
			}

			return nil, nil
		},
	)
}

func parseNamespacedNames(pods []string) ([]k8stypes.NamespacedName, error) {
	var parsedPods []k8stypes.NamespacedName

	for _, pod := range pods {
		parts := strings.Split(pod, "/")

		if len(parts) != 2 {
			return nil, fmt.Errorf("could not parse namespace/pod from %s", pod)
		}

		parsedPods = append(parsedPods, k8stypes.NamespacedName{
			Namespace: parts[0],
			Name:      parts[1],
		})
	}

	return parsedPods, nil
}

func flattenStats(stats []statstypes.BPFProgramStats) []bpfProgramStats {
	flattenedStats := make([]bpfProgramStats, len(stats))

	for i, rs := range stats {
		var ifaceName string
		if rs.Device != nil {
			ifaceName = rs.Device.Attrs().Name
		}
		progID, _ := rs.Info.ID()
		flattenedStats[i] = bpfProgramStats{
			ProgramID:    progID,
			ProgramName:  rs.Info.Name,
			ProgramType:  rs.Info.Type.String(),
			IfaceName:    ifaceName,
			PodNamespace: rs.Pod.Namespace,
			PodName:      rs.Pod.Name,
			TotalRuns:    rs.Stats.RunCount,
			TotalRuntime: rs.Stats.Runtime,
			AvgRuntimeNS: rs.AvgRuntimeNS(),
		}
	}

	return flattenedStats
}

func displayProgramStats(w io.Writer, stats []statstypes.BPFProgramStats, jsonOutput bool) error {
	if jsonOutput {
		bytes, err := json.MarshalIndent(flattenStats(stats), "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
		fmt.Fprint(w, string(bytes))
	} else {
		if len(stats) == 0 {
			fmt.Fprint(w, "No entries found.")
		} else {
			printResults(w, stats)
		}
	}
	return nil
}

func printResults(w io.Writer, res []statstypes.BPFProgramStats) {
	tw := tabwriter.NewWriter(w, 5, 0, 3, ' ', 0)

	fmt.Fprintln(tw, "DEVICE\tPOD\tBPF PROGRAM\tTYPE\tTOTAL RUNS\tTOTAL RUNTIME\tAVG RUNTIME")

	for i, r := range res {
		var devName string
		if r.Device != nil {
			devName = r.Device.Attrs().Name
		}
		fmt.Fprintf(
			tw, "%s\t%s\t%s\t%s\t%d\t%.2fs\t%d ns",
			devName,
			r.PodString(),
			r.Info.Name,
			r.Info.Type,
			r.Stats.RunCount,
			r.Stats.Runtime.Seconds(),
			r.AvgRuntimeNS().Nanoseconds(),
		)
		if i != len(res)-1 {
			fmt.Fprintf(tw, "\n")
		}
	}
	tw.Flush()
}

func getCompareFunc(sortField string, stats []statstypes.BPFProgramStats) (func(i, j int) bool, error) {
	switch strings.ToLower(sortField) {
	case "total":
		return func(i, j int) bool { return stats[i].Stats.Runtime > stats[j].Stats.Runtime }, nil
	case "runs":
		return func(i, j int) bool { return stats[i].Stats.RunCount > stats[j].Stats.RunCount }, nil
	case "avg":
		return func(i, j int) bool { return stats[i].AvgRuntimeNS() > stats[j].AvgRuntimeNS() }, nil
	default:
		return nil, fmt.Errorf("invalid sort field: %s. Expected: avg, total, runs", sortField)
	}
}
