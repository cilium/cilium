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
	"github.com/cilium/cilium/pkg/bgp/types"
)

const (
	locRibTable    = "loc"
	adjRibInTable  = "in"
	adjRibOutTable = "out"
	ipv6AFI        = "ipv6"
)

// GetRoutes gets BGP routes from all/specific cilium agent pods.
func (s *Status) GetRoutes(ctx context.Context, args []string) error {
	args = defaultGetRoutesArgs(args)
	err := validateGetRoutesArgs(args)
	if err != nil {
		return err
	}

	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	err = s.initTargetCiliumPods(ctx)
	if err != nil {
		return err
	}

	// compute the command for fetching the routes from a cilium pod
	fetchCmd := []string{"cilium-dbg", "shell", "--", "bgp/routes"}
	fetchCmd = append(fetchCmd, args...)
	fetchCmd = append(fetchCmd, "-f", "table-json")

	if s.params.ShowAttrs {
		fetchCmd = append(fetchCmd, "--with-attrs")
	}

	res, err := s.fetchCmdConcurrently(ctx, fetchCmd, s.fetchRoutesFromPod)
	if err != nil {
		if len(res) == 0 {
			// no results retrieved - just return the error
			return err
		}
		// print the errors, but continue with printing results
		fmt.Fprintf(os.Stderr, "Errors by retrieving routes: %v\n\n", err)
	}

	return s.writeRoutes(res, args[0], s.params.ShowAttrs)
}

func (s *Status) fetchRoutesFromPod(ctx context.Context, fetchCmd []string, pod *corev1.Pod) ([]string, error) {
	if err := s.checkCiliumVersion(ctx, pod); err != nil {
		return nil, fmt.Errorf("failed to fetch bgp state from %s: %w, use \"bgp legacy routes\" instead", pod.Name, err)
	}

	output, errOutput, err := s.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, fetchCmd)
	if err != nil {
		var errStr string
		if errOutput.String() != "" {
			errStr = strings.TrimSpace(errOutput.String())
		} else {
			errStr = err.Error()
		}
		return nil, fmt.Errorf("failed to fetch bgp state from %s: (%s)", pod.Name, errStr)
	}

	var table tableJSON
	err = json.Unmarshal(output.Bytes(), &table)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal bgp routes from %s: %w", pod.Name, err)
	}

	return table.ToStrings(), nil
}

func (s *Status) writeRoutes(res map[string][]string, tableType string, printAttr bool) error {
	printPeer := tableType == adjRibInTable || tableType == adjRibOutTable
	printRouteSummary(os.Stdout, res, printPeer, printAttr)

	return nil
}

func defaultGetRoutesArgs(args []string) []string {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "(Defaulting to `%s %s %s` routes, please see help for more options)\n\n", locRibTable, ipv4AFI, unicastSAFI)
		return []string{locRibTable, ipv4AFI, unicastSAFI}
	}
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "(Defaulting to `%s %s` AFI & SAFI, please see help for more options)\n\n", ipv4AFI, unicastSAFI)
		return []string{args[0], ipv4AFI, unicastSAFI}
	}
	if len(args) < 3 {
		fmt.Fprintf(os.Stderr, "(Defaulting to `%s` SAFI, please see help for more options)\n\n", unicastSAFI)
		return []string{args[0], args[1], unicastSAFI}
	}
	return args
}

func validateGetRoutesArgs(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing argument `%s` / `%s` / `%s`", locRibTable, adjRibInTable, adjRibOutTable)
	}

	// loc | in | out
	if args[0] != locRibTable && args[0] != adjRibInTable && args[0] != adjRibOutTable {
		return fmt.Errorf("invalid argument: `%s`, expected `%s` / `%s` / `%s`", args[0], locRibTable, adjRibInTable, adjRibOutTable)
	}

	// <afi> <safi>
	if len(args) < 2 {
		return fmt.Errorf("missing AFI value (e.g. `%s` / `%s`)", ipv4AFI, ipv6AFI)
	}
	if types.ParseAfi(args[1]) == types.AfiUnknown {
		return fmt.Errorf("unknown AFI `%s`", args[1])
	}
	if len(args) < 3 {
		return fmt.Errorf("missing SAFI value (e.g. `%s`)", unicastSAFI)
	}
	if types.ParseSafi(args[2]) == types.SafiUnknown {
		return fmt.Errorf("unknown SAFI `%s`", args[2])
	}

	return nil
}

func printRouteSummary(out io.Writer, routesPerNode map[string][]string, printPeer, printAttr bool) {
	// sort by node names
	nodes := slices.Sorted(maps.Keys(routesPerNode))
	w := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)

	for i, node := range nodes {
		rows := routesPerNode[node]

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
