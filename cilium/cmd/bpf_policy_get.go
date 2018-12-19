// Copyright 2017-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/spf13/cobra"
)

var (
	printIDs bool
	allList  bool
)

// bpfPolicyListCmd represents the bpf_policy_list command
var bpfPolicyListCmd = &cobra.Command{
	Use:   "get",
	Short: "List contents of a policy BPF map",
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
	bpfPolicyCmd.AddCommand(bpfPolicyListCmd)
	bpfPolicyListCmd.Flags().BoolVarP(&printIDs, "numeric", "n", false, "Do not resolve IDs")
	bpfPolicyListCmd.Flags().BoolVarP(&allList, "all", "", false, "Dump all policy maps")
	command.AddJSONOutput(bpfPolicyListCmd)
}

func listAllMaps() {
	mapRootPrefixPath := bpf.MapPrefixPath()
	mapMatchExpr := filepath.Join(mapRootPrefixPath, "cilium_policy_*")

	matchFiles, err := filepath.Glob(mapMatchExpr)
	if err != nil {
		log.Fatal(err)
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

	if lbl != "" {
		if id := identity.GetReservedID(lbl); id != identity.IdentityUnknown {
			lbl = "reserved_" + strconv.FormatUint(uint64(id), 10)
		}
	} else {
		Fatalf("Need ID or label\n")
	}

	file := bpf.MapPath(policymap.MapName + lbl)
	dumpMap(file)
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

	if command.OutputJSON() {
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
				labelsID[id] = identity.NewIdentityFromModel(lbls)
			}
		}

	}

	if printIDs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t\n", trafficDirectionTitle, labelsIDTitle, portTitle, proxyPortTitle, bytesTitle, packetsTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t\n", trafficDirectionTitle, labelsDesTitle, portTitle, proxyPortTitle, bytesTitle, packetsTitle)
	}
	for _, stat := range statsMap {
		id := identity.NumericIdentity(stat.Key.Identity)
		trafficDirection := trafficdirection.TrafficDirection(stat.Key.TrafficDirection)
		trafficDirectionString := trafficDirection.String()
		port := models.PortProtocolANY
		if stat.Key.DestPort != 0 {
			dport := byteorder.NetworkToHost(stat.Key.DestPort).(uint16)
			proto := u8proto.U8proto(stat.Key.Nexthdr)
			port = fmt.Sprintf("%d/%s", dport, proto.String())
		}
		proxyPort := "NONE"
		if stat.ProxyPort != 0 {
			proxyPort = strconv.FormatUint(uint64(byteorder.NetworkToHost(stat.ProxyPort).(uint16)), 10)
		}
		if printIDs {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%d\t%d\t\n", trafficDirectionString, id, port, proxyPort, stat.Bytes, stat.Packets)
		} else if lbls := labelsID[id]; lbls != nil && len(lbls.Labels) > 0 {
			first := true
			for _, lbl := range lbls.Labels.GetPrintableModel() {
				if first {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t\n", trafficDirectionString, lbl, port, proxyPort, stat.Bytes, stat.Packets)
					first = false
				} else {
					fmt.Fprintf(w, "\t%s\t\t\t\t\t\t\n", lbl)
				}
			}
		} else {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%d\t%d\t\n", trafficDirectionString, id, port, proxyPort, stat.Bytes, stat.Packets)
		}
	}
}
