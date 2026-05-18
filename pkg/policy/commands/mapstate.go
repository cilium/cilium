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

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

// msEntriesCmd dumps the mapstate entries, rather than the existing
// BPF policymap.
func msEntriesCmd(params CmdParams) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Display policy map state for a given endpoint",
			Args:    "<pod-or-endpoint>+",
			Flags: func(fs *pflag.FlagSet) {
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
				"List all MapState entries for some or all endpoints.",
				"The MapState is the *desired* contents of the BPF policy map.",
				"This command dumps the desired state as understood by the agent.",
				"",
				`pod-or-endpoint: either numerical endpoint ID or "namespace/podname", optionall repeateds`,
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(*script.State) (stdout, stderr string, err error) {
				format, err := s.Flags.GetString("format")
				if err != nil {
					return "", "", err
				}
				if format != "json" && format != "table" {
					return "", "", fmt.Errorf("unsupported format %s", format)
				}

				// Collect policy from all endpoints
				eps, err := lookupEPs(params.EPL, args)
				if err != nil {
					return "", "", err
				}
				outs := make([]entriesEPOut, 0, len(eps))

				for _, ep := range eps {
					epo := entriesEPOut{
						ID:        ep.ID,
						Namespace: ep.K8sNamespace,
						Name:      ep.K8sPodName,
					}
					policy := ep.GetDesiredPolicy()
					if policy != nil {
						for key, entry := range policy.Entries() {
							meta, _ := policy.GetRuleMeta(key)
							epo.Entries = append(epo.Entries, makeEntry(key, entry, meta))
						}
					}
					outs = append(outs, epo)
				}

				// sort by ID
				slices.SortFunc(outs, func(a, b entriesEPOut) int {
					return cmp.Compare(a.ID, b.ID)
				})

				// Output, in table or json format
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
						fmt.Fprintf(buf, "ID: %d\tNamespace: %s\tName: %s\tEntries:%d\n", ep.ID, ep.Namespace, ep.Name, len(ep.Entries))
						tw := tabwriter.NewWriter(buf, 5, 0, 3, ' ', 0)
						fmt.Fprintf(tw, "Direction\tIdentity\tProto+Port\tPriority\tListenerPrio\tVerdict\tProxyPort\tCookie\tOrigins\n")

						for _, row := range ep.Entries {
							fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%d\t%s\t%d\t%d\t%s\n",
								row.Direction,
								row.Identity,
								row.PortProto,
								row.Priority,
								row.ListenerPriority,
								row.Verdict,
								row.ProxyPort,
								row.Cookie,
								joinOrigins(row.Origins),
							)
						}
						tw.Flush()
						fmt.Fprintln(buf)
					}
					return buf.String(), "", nil
				}

				return "", "", fmt.Errorf("unsupported format %s", format)

			}, nil
		},
	)
}

type entriesEPOut struct {
	ID        uint16 `json:"id"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	Entries []entryOut `json:"entries"`
}

type entryOut struct {
	Direction string                   `json:"direction"`
	Identity  identity.NumericIdentity `json:"identity"`
	PortProto string                   `json:"portproto"`

	Priority         policytypes.Priority         `json:"priority"`
	ListenerPriority policytypes.ListenerPriority `json:"listenerpriority"`

	Verdict   string `json:"verdict"`
	ProxyPort uint16 `json:"proxyPort"`
	Cookie    uint32 `json:"cookie"`

	Origins []origin `json:"origins"`
}

func makeEntry(key policy.Key, entry policy.MapStateEntry, meta policy.RuleMeta) entryOut {
	out := entryOut{
		Direction: key.TrafficDirection().String(),
		Identity:  key.Identity,

		Priority:         entry.Precedence.Priority(),
		ListenerPriority: entry.Precedence.ListenerPriority(),

		Verdict:   "unknown",
		ProxyPort: entry.ProxyPort,
		Cookie:    entry.Cookie,
	}

	if key.Nexthdr == 0 {
		out.PortProto = "*"
	} else if key.HasPortWildcard() {
		out.PortProto = fmt.Sprintf("%s/%d-%d",
			key.Nexthdr.String(),
			key.DestPort,
			key.EndPort(),
		)
	} else {
		out.PortProto = fmt.Sprintf("%s/%d",
			key.Nexthdr.String(),
			key.DestPort,
		)
	}

	switch {
	case !entry.IsValid():
		out.Verdict = "invalid"
	case entry.IsDeny():
		out.Verdict = "deny"
	case entry.Precedence.IsPass():
		out.Verdict = "pass"
	case entry.IsAllow():
		out.Verdict = "allow"
	}

	for _, lbls := range meta.LabelArray() {
		out.Origins = append(out.Origins, summarizeOrigin(lbls))
	}

	return out
}
