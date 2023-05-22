// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
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
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
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
			listAllMaps()
			return
		}
		requireEndpointID(cmd, args)
		listMap(args)
	},
}

func init() {
	bpfPolicyCmd.AddCommand(bpfPolicyGetCmd)
	bpfPolicyGetCmd.Flags().BoolVarP(&printIDs, "numeric", "n", false, "Do not resolve IDs")
	bpfPolicyGetCmd.Flags().BoolVarP(&allList, "all", "", false, "Dump all policy maps")
	command.AddOutputOption(bpfPolicyGetCmd)
}

func listAllMaps() {
	mapRootPrefixPath := bpf.TCGlobalsPath()
	mapMatchExpr := filepath.Join(mapRootPrefixPath, "cilium_policy_*")

	matchFiles, err := filepath.Glob(mapMatchExpr)
	if err != nil {
		log.Fatal(err)
	}

	if len(matchFiles) == 0 {
		fmt.Println("no maps found")
		return
	}

	maps := []policyMap{}
	for _, file := range matchFiles {
		endpointSplit := strings.Split(file, "_")
		endpoint := strings.TrimLeft(endpointSplit[len(endpointSplit)-1], "0")
		maps = append(maps, policyMap{
			EndpointID: endpoint,
			Path:       file,
			Content:    mapContent(file),
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
	Content    policymap.PolicyEntriesDump
}

func listMap(args []string) {
	lbl := args[0]

	mapPath, err := endpointToPolicyMapPath(lbl)
	if err != nil {
		Fatalf("Failed to parse endpointID %q", lbl)
	}

	contentDump := mapContent(mapPath)
	if command.OutputOption() {
		if err := command.PrintOutput(contentDump); err != nil {
			os.Exit(1)
		}
	} else {
		printTable(contentDump)
	}
}

func mapContent(file string) policymap.PolicyEntriesDump {
	m, err := policymap.Open(file)
	if err != nil {
		Fatalf("Failed to open map: %s\n", err)
	}
	defer m.Close()

	statsMap, err := m.DumpToSlice()
	if err != nil {
		Fatalf("Error while opening bpf Map: %s\n", err)
	}
	sort.Slice(statsMap, statsMap.Less)

	return statsMap
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
		authTypeTitle         = "AUTH TYPE"
		bytesTitle            = "BYTES"
		packetsTitle          = "PACKETS"
		prefixTitle           = "PREFIX"
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			policyTitle, trafficDirectionTitle, labelsIDTitle, portTitle, proxyPortTitle, authTypeTitle, bytesTitle, packetsTitle, prefixTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			policyTitle, trafficDirectionTitle, labelsDesTitle, portTitle, proxyPortTitle, authTypeTitle, bytesTitle, packetsTitle, prefixTitle)
	}
	for _, stat := range statsMap {
		prefixLen := stat.Key.Prefixlen - policymap.StaticPrefixBits
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
		if printIDs {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%d\t%d\t%d\t\n",
				policyStr, trafficDirectionString, id, port, proxyPort, policy.AuthType(stat.AuthType), stat.Bytes, stat.Packets, prefixLen)
		} else if lbls := labelsID[id]; lbls != nil && len(lbls.Labels) > 0 {
			first := true
			for _, lbl := range lbls.Labels.GetPrintableModel() {
				if first {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t\n",
						policyStr, trafficDirectionString, lbl, port, proxyPort, policy.AuthType(stat.AuthType), stat.Bytes, stat.Packets, prefixLen)
					first = false
				} else {
					fmt.Fprintf(w, "\t\t%s\t\t\t\t\t\t\t\n", lbl)
				}
			}
		} else {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%d\t%d\t%d\t\n",
				policyStr, trafficDirectionString, id, port, proxyPort, policy.AuthType(stat.AuthType), stat.Bytes, stat.Packets, prefixLen)
		}
	}
}
