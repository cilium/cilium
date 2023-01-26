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
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/identity"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
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

	for _, file := range matchFiles {
		fmt.Printf("%s:\n", file)
		fmt.Println()
		dumpMap(file)
		fmt.Println()
		fmt.Println()
	}
}

func listMap(args []string) {
	lbl := args[0]

	mapPath, err := endpointToPolicyMapPath(lbl)
	if err != nil {
		Fatalf("Failed to parse endpointID %q", lbl)
	}
	dumpMap(mapPath)
}

func dumpMap(file string) {
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

	if command.OutputOption() {
		if err := command.PrintOutput(statsMap); err != nil {
			os.Exit(1)
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		formatMap(w, statsMap)
		w.Flush()
		if len(statsMap) == 0 {
			fmt.Printf("Policy stats empty. Perhaps the policy enforcement is disabled?\n")
		}
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			policyTitle, trafficDirectionTitle, labelsIDTitle, portTitle, proxyPortTitle, bytesTitle, packetsTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			policyTitle, trafficDirectionTitle, labelsDesTitle, portTitle, proxyPortTitle, bytesTitle, packetsTitle)
	}
	for _, stat := range statsMap {
		id := identity.NumericIdentity(stat.Key.Identity)
		trafficDirection := trafficdirection.TrafficDirection(stat.Key.TrafficDirection)
		trafficDirectionString := trafficDirection.String()
		port := models.PortProtocolANY
		if stat.Key.DestPort != 0 || stat.Key.Nexthdr == uint8(u8proto.ICMP) || stat.Key.Nexthdr == uint8(u8proto.ICMPv6) {
			dport := byteorder.NetworkToHost16(stat.Key.DestPort)
			proto := u8proto.U8proto(stat.Key.Nexthdr)
			port = fmt.Sprintf("%d/%s", dport, proto.String())
		}
		proxyPort := "NONE"
		if stat.ProxyPort != 0 {
			proxyPort = strconv.FormatUint(uint64(byteorder.NetworkToHost16(stat.ProxyPort)), 10)
		}
		var policyStr string
		if policymap.PolicyEntryFlags(stat.Flags).IsDeny() {
			policyStr = "Deny"
		} else {
			policyStr = "Allow"
		}
		if printIDs {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%d\t\n",
				policyStr, trafficDirectionString, id, port, proxyPort, stat.Bytes, stat.Packets)
		} else if lbls := labelsID[id]; lbls != nil && len(lbls.Labels) > 0 {
			first := true
			for _, lbl := range lbls.Labels.GetPrintableModel() {
				if first {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t\n",
						policyStr, trafficDirectionString, lbl, port, proxyPort, stat.Bytes, stat.Packets)
					first = false
				} else {
					fmt.Fprintf(w, "\t\t%s\t\t\t\t\t\t\n", lbl)
				}
			}
		} else {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%d\t\n",
				policyStr, trafficDirectionString, id, port, proxyPort, stat.Bytes, stat.Packets)
		}
	}
}
