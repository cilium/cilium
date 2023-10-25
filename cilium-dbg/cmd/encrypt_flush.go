// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/common/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
)

const (
	spiFlagName = "spi"
)

var encryptFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flushes the current IPsec state",
	Long:  "Will cause a short connectivity disruption",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium encrypt flush")
		runXFRMFlush()
	},
}

var (
	spiToFilter uint8
)

func runXFRMFlush() {
	if spiToFilter == 0 {
		flushEverything()
		return
	}

	if spiToFilter > linux_defaults.IPsecMaxKeyVersion {
		Fatalf("Given SPI is too big")
	}

	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		Fatalf("Failed to retrieve XFRM states: %s", err)
	}
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		Fatalf("Failed to retrieve XFRM policies: %s", err)
	}
	nbStates := len(states)
	nbPolicies := len(policies)

	policies, states = filterXFRMBySPI(policies, states)
	if len(policies) == nbPolicies || len(states) == nbStates {
		confirmationMsg := "Running this command will delete all XFRM state and/or policies. " +
			"It will lead to transient connectivity disruption and plain-text pod-to-pod traffic."
		if !confirmXFRMCleanup(confirmationMsg) {
			return
		}
	}

	for _, state := range states {
		if err := netlink.XfrmStateDel(&state); err != nil {
			Fatalf("Stopped XFRM states deletion due to error: %s", err)
		}
	}
	fmt.Printf("Deleted %d XFRM states.\n", len(states))
	for _, pol := range policies {
		if err := netlink.XfrmPolicyDel(&pol); err != nil {
			Fatalf("Stopped XFRM policies deletion due to error: %s", err)
		}
	}
	fmt.Printf("Deleted %d XFRM policies.\n", len(policies))
}

func filterXFRMBySPI(policies []netlink.XfrmPolicy, states []netlink.XfrmState) ([]netlink.XfrmPolicy, []netlink.XfrmState) {
	policiesToDel := []netlink.XfrmPolicy{}
	for _, pol := range policies {
		if ipsec.GetSPIFromXfrmPolicy(&pol) == spiToFilter {
			policiesToDel = append(policiesToDel, pol)
		}
	}

	statesToDel := []netlink.XfrmState{}
	for _, state := range states {
		if state.Spi == int(spiToFilter) {
			statesToDel = append(statesToDel, state)
		}
	}

	return policiesToDel, statesToDel
}

func flushEverything() {
	confirmationMsg := "Flushing all XFRM states and policies can lead to transient " +
		"connectivity interruption and plain-text pod-to-pod traffic."
	if !confirmXFRMCleanup(confirmationMsg) {
		return
	}
	netlink.XfrmPolicyFlush()
	netlink.XfrmStateFlush(netlink.XFRM_PROTO_ESP)
	fmt.Println("All XFRM states and policies have been deleted.")
}

func confirmXFRMCleanup(msg string) bool {
	if force {
		return true
	}
	var res string
	fmt.Printf("%s Do you want to continue? [y/N] ", msg)
	fmt.Scanln(&res)
	return res == "y"
}

func init() {
	encryptFlushCmd.Flags().BoolVarP(&force, forceFlagName, "f", false, "Skip confirmation")
	encryptFlushCmd.Flags().Uint8Var(&spiToFilter, spiFlagName, 0, "Only delete states and policies with this SPI")
	CncryptCmd.AddCommand(encryptFlushCmd)
	command.AddOutputOption(encryptFlushCmd)
}
