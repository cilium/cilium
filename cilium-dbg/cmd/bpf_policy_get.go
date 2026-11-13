// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/identity"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

var (
	printIDs bool
	allList  bool
)

// bpfPolicyGetCmd represents the bpf_policy_get command
var bpfPolicyGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get contents of a policy BPF map",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf policy get")
		if allList {
			listAllMaps(log)
			return
		}
		requireEndpointID(cmd, args)
		listMap(log, args)
	},
}

func init() {
	BPFPolicyCmd.AddCommand(bpfPolicyGetCmd)
	bpfPolicyGetCmd.Flags().BoolVarP(&printIDs, "numeric", "n", false, "Do not resolve IDs")
	bpfPolicyGetCmd.Flags().BoolVarP(&allList, "all", "", false, "Dump all policy maps")
	command.AddOutputOption(bpfPolicyGetCmd)
}

func listAllMaps(logger *slog.Logger) {
	mapRootPrefixPath := bpf.TCGlobalsPath()
	mapMatchExpr := filepath.Join(mapRootPrefixPath, "cilium_policy_*")

	matchFiles, err := filepath.Glob(mapMatchExpr)
	if err != nil {
		logging.Fatal(logger, err.Error())
	}

	var endpointFiles []string
	seen := make(map[string]struct{}, len(matchFiles))
	for _, file := range matchFiles {
		base := filepath.Base(file)
		if base == policymap.SharedPolicyMapName || base == policymap.PolicyOverlayMapName {
			continue
		}
		endpointFiles = append(endpointFiles, file)
		seen[file] = struct{}{}
	}
	overlayPath := filepath.Join(mapRootPrefixPath, policymap.PolicyOverlayMapName)
	if epIDs, err := policymap.OpenOverlayEndpointIDs(overlayPath); err == nil {
		for _, epID := range epIDs {
			epPath := bpf.LocalMapPath(logger, policymap.MapName, epID)
			if _, ok := seen[epPath]; !ok {
				endpointFiles = append(endpointFiles, epPath)
				seen[epPath] = struct{}{}
			}
		}
	}

	if len(endpointFiles) == 0 {
		fmt.Println("no maps found")
		return
	}

	maps := []policyMap{}
	for _, file := range endpointFiles {
		endpointSplit := strings.Split(file, "_")
		endpoint := strings.TrimLeft(endpointSplit[len(endpointSplit)-1], "0")
		content, path, ruleSetID := mapContent(logger, file)
		maps = append(maps, policyMap{
			EndpointID: endpoint,
			Path:       path,
			RuleSetID:  ruleSetID,
			Content:    content,
		})
	}

	if command.OutputOption() {
		if err := command.PrintOutput(maps); err != nil {
			os.Exit(1)
		}
	} else {
		for _, m := range maps {
			fmt.Printf("Endpoint ID: %s\n", m.EndpointID)
			fmt.Printf("Path: %s\n", m.Path)
			if m.RuleSetID != 0 {
				fmt.Printf("Rule set: %d\n", m.RuleSetID)
			}
			fmt.Println()
			printTable(m.Content)
			fmt.Println()
			fmt.Println()
		}
	}
}

type policyMap struct {
	EndpointID string
	Path       string
	RuleSetID  uint32 `json:",omitempty"`
	Content    policymap.PolicyEntriesDump
}

func listMap(logger *slog.Logger, args []string) {
	lbl := args[0]

	mapPath, err := endpointToPolicyMapPath(logger, lbl)
	if err != nil {
		Fatalf("Failed to parse endpointID %q", lbl)
	}

	contentDump, _, _ := mapContent(logger, mapPath)
	if command.OutputOption() {
		if err := command.PrintOutput(contentDump); err != nil {
			os.Exit(1)
		}
	} else {
		printTable(contentDump)
	}
}

// mapContent returns the policy entries of the endpoint whose per-endpoint policy map path is
// 'file', along with the path of the map they were read from and, if that is the shared
// policy map, the endpoint's rule set ID (0 otherwise).
func mapContent(logger *slog.Logger, file string) (policymap.PolicyEntriesDump, string, uint32) {
	m, err := policymap.OpenPolicyMap(logger, file)
	if err != nil {
		Fatalf("Failed to open map: %s\n", err)
	}
	defer m.Close()

	statsMap, err := m.DumpToSlice()
	if err != nil {
		Fatalf("Error while opening bpf Map: %s\n", err)
	}
	sort.Slice(statsMap, statsMap.Less)

	ruleSetID, shared := m.SharedRuleSet()
	if !shared {
		return statsMap, file, 0
	}
	return statsMap, filepath.Join(filepath.Dir(file), policymap.SharedPolicyMapName), ruleSetID
}

func printTable(contentDump policymap.PolicyEntriesDump) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	formatMap(w, contentDump)
	w.Flush()
	if len(contentDump) == 0 {
		fmt.Printf("Policy stats empty. Perhaps the policy enforcement is disabled?\n")
	}
}

func formatMap(w io.Writer, statsMap []policymap.PolicyEntryDump) {
	const (
		policyTitle           = "POLICY"
		trafficDirectionTitle = "DIRECTION"
		labelsIDTitle         = "IDENTITY"
		labelsDesTitle        = "LABELS (source:key[=value])"
		portTitle             = "PORT/PROTO"
		proxyPortTitle        = "PROXY PORT"
		bytesTitle            = "BYTES"
		packetsTitle          = "PACKETS"
		prefixTitle           = "PREFIX"
		cookieTitle           = "COOKIE"
	)

	labelsID := map[identity.NumericIdentity]*identity.Identity{}
	for _, stat := range statsMap {
		if !printIDs {
			id := identity.NumericIdentity(stat.Key.Identity)
			if lbls, err := client.IdentityGet(id.StringID()); err != nil {
				fmt.Fprintf(os.Stderr, "Was impossible to retrieve label ID %d: %s\n",
					id, err)
			} else {
				labelsID[id] = identitymodel.NewIdentityFromModel(lbls)
			}
		}

	}

	if printIDs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			policyTitle, trafficDirectionTitle, labelsIDTitle, portTitle, proxyPortTitle, bytesTitle, packetsTitle, prefixTitle, cookieTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			policyTitle, trafficDirectionTitle, labelsDesTitle, portTitle, proxyPortTitle, bytesTitle, packetsTitle, prefixTitle, cookieTitle)
	}
	for _, stat := range statsMap {
		prefixLen := stat.Key.GetPrefixLen()
		id := identity.NumericIdentity(stat.Key.Identity)
		trafficDirection := trafficdirection.TrafficDirection(stat.Key.TrafficDirection)
		trafficDirectionString := trafficDirection.String()
		port := stat.Key.PortProtoString()
		proxyPort := "NONE"
		pp := stat.GetProxyPort()
		if pp != 0 {
			proxyPort = strconv.FormatUint(uint64(pp), 10)
		}
		var policyStr string
		if stat.IsDeny() {
			policyStr = "Deny"
		} else {
			policyStr = "Allow"
		}
		packets := "-"
		if stat.Packets != policymap.StatNotAvailable {
			packets = strconv.FormatUint(stat.Packets, 10)
		}
		bytes := "-"
		if stat.Bytes != policymap.StatNotAvailable {
			bytes = strconv.FormatUint(stat.Bytes, 10)
		}
		cookie := stat.Cookie
		if printIDs {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\n",
				policyStr, trafficDirectionString, id, port, proxyPort, bytes, packets, prefixLen, cookie)
		} else if lbls := labelsID[id]; lbls != nil && len(lbls.Labels) > 0 {
			first := true
			for _, lbl := range lbls.Labels.GetPrintableModel() {
				if lbl == "reserved:unknown" {
					lbl = "ANY"
				}
				if first {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
						policyStr, trafficDirectionString, lbl, port, proxyPort, bytes, packets, prefixLen, cookie)
					first = false
				} else {
					fmt.Fprintf(w, "\t\t%s\t\t\t\t\t\t\n", lbl)
				}
			}
		} else {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\n",
				policyStr, trafficDirectionString, id, port, proxyPort, bytes, packets, prefixLen, cookie)
		}
	}
}
