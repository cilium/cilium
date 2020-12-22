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

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	"github.com/spf13/cobra"
)

const (
	idTitle             = "ID"
	serviceAddressTitle = "SERVICE ADDRESS"
	backendAddressTitle = "BACKEND ADDRESS"
)

var (
	listRevNAT bool
)

func dumpRevNat(serviceList map[string][]string) {
	if err := lbmap.RevNat4Map.DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv4 reverse NAT table: %s", err)
	}
	if err := lbmap.RevNat6Map.DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv6 reverse NAT table: %s", err)
	}
}

func dumpSVC(serviceList map[string][]string) {
	// It's safe to use the same map for both IPv4 and IPv6, as backend
	// IDs are allocated from the same pool regardless the protocol
	backendMap := make(map[loadbalancer.BackendID]lbmap.BackendValue)

	parseBackendEntry := func(key bpf.MapKey, value bpf.MapValue) {
		id := key.(lbmap.BackendKey).GetID()
		backendMap[id] = value.DeepCopyMapValue().(lbmap.BackendValue).ToHost()
	}
	if err := lbmap.Backend4Map.DumpWithCallbackIfExists(parseBackendEntry); err != nil {
		Fatalf("Unable to dump IPv4 backends table: %s", err)
	}
	if err := lbmap.Backend6Map.DumpWithCallbackIfExists(parseBackendEntry); err != nil {
		Fatalf("Unable to dump IPv6 backends table: %s", err)
	}

	parseSVCEntry := func(key bpf.MapKey, value bpf.MapValue) {
		var entry string

		svcKey := key.(lbmap.ServiceKey)
		svcVal := value.(lbmap.ServiceValue).ToHost()
		svc := svcKey.String()
		svcKey = svcKey.ToHost()
		revNATID := svcVal.GetRevNat()
		backendID := svcVal.GetBackendID()
		flags := loadbalancer.ServiceFlags(svcVal.GetFlags())

		if svcKey.GetBackendSlot() == 0 {
			ip := "0.0.0.0"
			if svcKey.IsIPv6() {
				ip = "[::]"
			}
			entry = fmt.Sprintf("%s:%d (%d) [%s]", ip, 0, revNATID, flags)
		} else if backend, found := backendMap[backendID]; !found {
			entry = fmt.Sprintf("backend %d not found", backendID)
		} else {
			fmtStr := "%s:%d (%d)"
			if svcKey.IsIPv6() {
				fmtStr = "[%s]:%d (%d)"
			}
			entry = fmt.Sprintf(fmtStr, backend.GetAddress(),
				backend.GetPort(), revNATID)
		}

		serviceList[svc] = append(serviceList[svc], entry)
	}

	if err := lbmap.Service4MapV2.DumpWithCallbackIfExists(parseSVCEntry); err != nil {
		Fatalf("Unable to dump IPv4 services table: %s", err)
	}
	if err := lbmap.Service6MapV2.DumpWithCallbackIfExists(parseSVCEntry); err != nil {
		Fatalf("Unable to dump IPv6 services table: %s", err)
	}
}

// bpfLBListCmd represents the bpf_lb_list command
var bpfLBListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List load-balancing configuration",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb list")

		var firstTitle string
		serviceList := make(map[string][]string)
		switch {
		case listRevNAT:
			firstTitle = idTitle
			dumpRevNat(serviceList)
		default:
			firstTitle = serviceAddressTitle
			dumpSVC(serviceList)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(serviceList); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter(firstTitle, backendAddressTitle, serviceList)
	},
}

func init() {
	bpfLBCmd.AddCommand(bpfLBListCmd)
	bpfLBListCmd.Flags().BoolVarP(&listRevNAT, "revnat", "", false, "List reverse NAT entries")
	command.AddJSONOutput(bpfLBListCmd)
}
