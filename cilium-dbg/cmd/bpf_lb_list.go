// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	idTitle             = "ID"
	serviceAddressTitle = "SERVICE ADDRESS"
	backendIdTitle      = "BACKEND ID"
	backendAddressTitle = "BACKEND ADDRESS (REVNAT_ID) (SLOT)"
	srcRangeTitle       = "SOURCE RANGE (REVNAT_ID)"
)

var (
	listRevNAT, listFrontends, listBackends, listSrcRanges bool
)

func dumpSrcRanges(serviceList map[string][]string) {
	if err := lbmaps.NewSourceRange4Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv4 source range table: %s", err)
	}
	if err := lbmaps.NewSourceRange6Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv6 source range table: %s", err)
	}
}

func dumpRevNat(serviceList map[string][]string) {
	if err := lbmaps.NewRevNat4Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv4 reverse NAT table: %s", err)
	}
	if err := lbmaps.NewRevNat6Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv6 reverse NAT table: %s", err)
	}
}

func dumpFrontends(serviceList map[string][]string) {
	if err := lbmaps.NewService4Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv4 frontend table: %s", err)
	}
	if err := lbmaps.NewService6Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv6 frontend table: %s", err)
	}
}

func dumpBackends(serviceList map[string][]string) {
	if err := lbmaps.NewBackend4Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv4 backend table: %s", err)
	}
	if err := lbmaps.NewBackend6Map(0).DumpIfExists(serviceList); err != nil {
		Fatalf("Unable to dump IPv6 backend table: %s", err)
	}
}

func dumpSVC(serviceList map[string][]string) {
	// It's safe to use the same map for both IPv4 and IPv6, as backend
	// IDs are allocated from the same pool regardless the protocol
	backendMap := make(map[loadbalancer.BackendID]lbmaps.BackendValue)

	parseBackendEntry := func(key bpf.MapKey, value bpf.MapValue) {
		id := key.(lbmaps.BackendKey).GetID()
		backendMap[id] = value.(lbmaps.BackendValue).ToHost()
	}
	if err := lbmaps.NewBackend4Map(0).DumpWithCallbackIfExists(parseBackendEntry); err != nil {
		Fatalf("Unable to dump IPv4 backends table: %s", err)
	}
	if err := lbmaps.NewBackend6Map(0).DumpWithCallbackIfExists(parseBackendEntry); err != nil {
		Fatalf("Unable to dump IPv6 backends table: %s", err)
	}

	parseSVCEntry := func(key bpf.MapKey, value bpf.MapValue) {
		var entry string

		svcKey := key.(lbmaps.ServiceKey)
		svcVal := value.(lbmaps.ServiceValue).ToHost()
		svc := svcKey.String()
		svcKey = svcKey.ToHost()
		backendSlot := svcKey.GetBackendSlot()
		revNATID := svcVal.GetRevNat()
		backendID := svcVal.GetBackendID()
		flags := loadbalancer.ServiceFlags(svcVal.GetFlags())

		if backendSlot == 0 {
			ip := "0.0.0.0"
			if svcKey.IsIPv6() {
				ip = "[::]"
			}
			extra := ""
			if flags.IsL7LB() {
				extra = fmt.Sprintf("(L7LB Proxy Port: %d)", byteorder.NetworkToHost16(uint16(svcVal.GetBackendID())))
			}
			entry = fmt.Sprintf("%s:%d (%d) (%d) [%s] %s", ip, 0, revNATID, backendSlot, flags, extra)
		} else if backend, found := backendMap[backendID]; !found {
			entry = fmt.Sprintf("backend %d not found", backendID)
		} else {
			fmtStr := "%s:%d/%s (%d) (%d)"
			if svcKey.IsIPv6() {
				fmtStr = "[%s]:%d/%s (%d) (%d)"
			}
			entry = fmt.Sprintf(fmtStr, backend.GetAddress(),
				backend.GetPort(), u8proto.U8proto(backend.GetProtocol()).String(), revNATID, backendSlot)
		}

		serviceList[svc] = append(serviceList[svc], entry)
	}

	if err := lbmaps.NewService4Map(0).DumpWithCallbackIfExists(parseSVCEntry); err != nil {
		Fatalf("Unable to dump IPv4 services table: %s", err)
	}
	if err := lbmaps.NewService6Map(0).DumpWithCallbackIfExists(parseSVCEntry); err != nil {
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
		secondTitle := backendAddressTitle
		serviceList := make(map[string][]string)
		switch {
		case listRevNAT:
			firstTitle = idTitle
			dumpRevNat(serviceList)
		case listFrontends:
			firstTitle = serviceAddressTitle
			secondTitle = backendIdTitle
			dumpFrontends(serviceList)
		case listBackends:
			firstTitle = idTitle
			dumpBackends(serviceList)
		case listSrcRanges:
			firstTitle = srcRangeTitle
			secondTitle = ""
			dumpSrcRanges(serviceList)
		default:
			firstTitle = serviceAddressTitle
			dumpSVC(serviceList)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(serviceList); err != nil {
				Fatalf("Unable to generate %s output: %s", command.OutputOptionString(), err)
			}
			return
		}

		TablePrinter(firstTitle, secondTitle, serviceList)
	},
}

func init() {
	BPFLBCmd.AddCommand(bpfLBListCmd)
	bpfLBListCmd.Flags().BoolVarP(&listRevNAT, "revnat", "", false, "List reverse NAT entries")
	bpfLBListCmd.Flags().BoolVarP(&listFrontends, "frontends", "", false, "List all service frontend entries")
	bpfLBListCmd.Flags().BoolVarP(&listBackends, "backends", "", false, "List all service backend entries")
	bpfLBListCmd.Flags().BoolVarP(&listSrcRanges, "source-ranges", "", false, "List all source range entries")
	command.AddOutputOption(bpfLBListCmd)
}
