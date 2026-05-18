// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/endpoint"
)

// topKCmd returns a command that indicates the resources
// responsible for the most mapstate entries.
func topKCmd(params CmdParams) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Determine causes of mapstate entries",
			Args:    "<pod-or-endpoint>",
			Flags: func(fs *pflag.FlagSet) {
				fs.IntP("num", "n", 10, "Maxiumum number of rows per endpoint to display")
				fs.IntP("count", "c", 0, "Maxiumum number of endpoints to display")
				fs.StringP("format", "f", "table", "Format to write in (table, json)")
			},
			AutocompleteFlag: func(_ *script.State, _ []string, flag, cur string) []string {
				switch flag {
				case "format":
					return filterPrefix([]string{"table", "json"}, cur)
				}
				return nil
			},
			AutocompleteArgs: autocompleteEndpoints(params),
			Detail: []string{
				"List policies and the number of mapstate entries they cause.",
				"",
				"NOTE: multiple policies may insert the same mapstate entries.",
				"The total may not be the exact sum.",
				"",
				`pod-or-endpoint: either numerical endpoint ID or "namespace/podname"`,
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(*script.State) (stdout, stderr string, err error) {
				num, err := s.Flags.GetInt("num")
				if err != nil {
					return "", "", err
				}
				count, err := s.Flags.GetInt("count")
				if err != nil {
					return "", "", err
				}
				format, err := s.Flags.GetString("format")
				if err != nil {
					return "", "", err
				}
				if format != "json" && format != "table" {
					return "", "", fmt.Errorf("unsupported format %s", format)
				}

				eps, err := lookupEPs(params.EPL, args)
				if err != nil {
					return "", "", err
				}
				outs := make([]topKEPOut, 0, len(eps))
				for _, ep := range eps {
					outs = append(outs, gatherEPTopK(ep, num))
				}

				// Sort by largest mapstate
				slices.SortFunc(outs, func(a, b topKEPOut) int {
					return cmp.Compare(b.Total, a.Total) // reverse sort
				})

				if count > 0 {
					outs = outs[:min(len(outs), count)]
				}

				switch format {
				case "json":
					b, err := json.MarshalIndent(outs, "", "\t")
					if err != nil {
						return "", "", fmt.Errorf("json marshal failed: %w", err)
					}
					return string(b), "", nil
				case "table":
					buf := &strings.Builder{}

					for _, ep := range outs {
						fmt.Fprintf(buf, "ID: %d\tNamespace: %s\tName: %s\tEntries: %d (may not sum)\tPolicies: %d\n", ep.ID, ep.Namespace, ep.Name, ep.Total, ep.NumOrigins)

						tw := tabwriter.NewWriter(buf, 5, 0, 3, ' ', 0)
						fmt.Fprintf(tw, "Policy\tEntries\n")

						for _, origin := range ep.Origins {
							fmt.Fprintf(tw, "%s\t%d\n", origin.String(), origin.Count)
						}
						tw.Flush()
						fmt.Fprintln(buf)
					}
					return buf.String(), "", nil
				}
				return "", "", nil
			}, nil
		},
	)
}

func gatherEPTopK(ep *endpoint.Endpoint, num int) topKEPOut {
	out := topKEPOut{
		ID:        ep.ID,
		Namespace: ep.K8sNamespace,
		Name:      ep.K8sPodName,
	}

	policy := ep.GetDesiredPolicy()
	if policy == nil {
		return out
	}
	out.Total = policy.Len()

	totals := map[origin]int{}

	for key := range policy.Entries() {
		meta, _ := policy.GetRuleMeta(key)
		for _, lbls := range meta.LabelArray() {
			origin := summarizeOrigin(lbls)
			totals[origin] = totals[origin] + 1
		}
	}

	out.Origins = make([]topKOrigin, 0, len(totals))

	for origin, count := range totals {
		out.Origins = append(out.Origins, topKOrigin{origin: origin, Count: count})
	}

	slices.SortFunc(out.Origins, func(a, b topKOrigin) int {
		// want topk, so reverse order
		return cmp.Compare(b.Count, a.Count)
	})

	out.NumOrigins = len(out.Origins)
	out.Origins = out.Origins[:min(len(out.Origins), num)]
	return out
}

type topKEPOut struct {
	ID        uint16 `json:"id"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	Origins []topKOrigin `json:"origins"`

	// Total number of entries
	Total int `json:"total"`

	// Total number of unique origins
	NumOrigins int `json:"numOrigins"`
}

type topKOrigin struct {
	origin

	Count int `json:"count"`
}
