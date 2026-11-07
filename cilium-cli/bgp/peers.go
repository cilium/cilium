// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/status"
)

// GetPeeringState gets peering state from all/specific cilium agent pods.
func (s *Status) GetPeeringState(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	err := s.initTargetCiliumPods(ctx)
	if err != nil {
		return err
	}

	var fetchCmd []string
	switch s.params.Output {
	case status.FormatTable:
		fetchCmd = []string{"cilium-dbg", "shell", "--", "bgp/peers", "-f", "table-json"}
	case status.FormatDetailed:
		fetchCmd = []string{"cilium-dbg", "shell", "--", "bgp/peers", "-f", "detailed"}
	default:
		return fmt.Errorf("unsupported format: %s", s.params.Output)
	}

	res, err := s.fetchCmdConcurrently(ctx, fetchCmd, s.fetchPeeringStateFromPod)
	if err != nil {
		if len(res) == 0 {
			// no results retrieved - just return the error
			return err
		}
		// print the errors, but continue with printing results
		fmt.Fprintf(os.Stderr, "Errors retrieving peering state: %v\n\n", err)
	}

	return s.writePeeringState(res)
}

func (s *Status) fetchPeeringStateFromPod(ctx context.Context, fetchCmd []string, pod *corev1.Pod) ([]string, error) {
	if err := s.checkCiliumVersion(ctx, pod); err != nil {
		return nil, fmt.Errorf("failed to fetch bgp state from %s: %w, use \"bgp legacy peers\" instead", pod.Name, err)
	}

	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, fetchCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bgp state from %s: %w", pod.Name, err)
	}

	bgpPeers := make([]string, 0)

	switch s.params.Output {
	case status.FormatTable:
		var table tableJSON
		if err = json.Unmarshal(output.Bytes(), &table); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bgp state from %s: %w", pod.Name, err)
		}
		bgpPeers = table.ToStrings()
	case status.FormatDetailed:
		bgpPeers = strings.FieldsFunc(output.String(), func(c rune) bool {
			return c == '\n'
		})
	}

	return bgpPeers, nil
}

func (s *Status) writePeeringState(res map[string][]string) error {
	switch s.params.Output {
	case status.FormatTable:
		printSummary(os.Stdout, res)
	case status.FormatDetailed:
		printDetailed(os.Stdout, res)
	}

	return nil
}

func printSummary(out io.Writer, peersPerNode map[string][]string) {
	// sort by node names
	nodes := slices.Sorted(maps.Keys(peersPerNode))
	// tab writer with min width 5 and padding 3
	w := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)

	for i, node := range nodes {
		rows := peersPerNode[node]

		if i == 0 {
			fmt.Fprintf(w, "Node\t%s\n", rows[0])
		}

		for j, row := range rows[1:] {
			if j == 0 {
				// print name for first row of peers
				fmt.Fprintf(w, "%s\t", node)
			} else {
				// skip name for all rest of the peers
				fmt.Fprint(w, "\t")
			}

			fmt.Fprintln(w, row)
		}
	}
	w.Flush()
}

func printDetailed(w io.Writer, peersPerNode map[string][]string) {
	// sort by node names
	nodes := slices.Sorted(maps.Keys(peersPerNode))

	for _, node := range nodes {
		rows := peersPerNode[node]
		fmt.Fprintf(w, "Node: %s\n", node)

		for _, row := range rows {
			fmt.Fprintf(w, "  %s\n", row)
		}
	}
}
