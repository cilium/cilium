// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/common/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
)

const (
	spiFlagName    = "spi"
	nodeIDFlagName = "node-id"
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
	spiToFilter    uint8
	nodeIDToFilter uint16
	nodeIDParam    string
)

func runXFRMFlush() {
	if spiToFilter == 0 && nodeIDParam == "" {
		flushEverything()
		return
	}

	if spiToFilter > linux_defaults.IPsecMaxKeyVersion {
		Fatalf("Given SPI is too big")
	}

	if nodeIDParam != "" {
		var err error
		nodeIDToFilter, err = parseNodeID(nodeIDParam)
		if err != nil {
			Fatalf("Unable to parse node ID %q: %s", nodeIDParam, err)
		}
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

	if spiToFilter != 0 {
		policies, states = filterXFRMBySPI(policies, states)
	}
	if nodeIDToFilter != 0 {
		policies, states = filterXFRMByNodeID(policies, states)
	}

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

func parseNodeID(nodeID string) (uint16, error) {
	var (
		val int64
		err error
	)

	if strings.HasPrefix(nodeID, "0x") {
		val, err = strconv.ParseInt(nodeID[2:], 16, 0)
		if err != nil {
			return 0, err
		}
	} else {
		val, err = strconv.ParseInt(nodeID, 10, 0)
		if err != nil {
			return 0, err
		}
	}

	if val == 0 {
		return 0, fmt.Errorf("0 is not a valid node ID in this context")
	}

	if val < 0 || val > int64(^uint16(0)) {
		return 0, fmt.Errorf("given node ID doesn't fit in uint16")
	}
	return uint16(val), nil
}

type policyFilter func(netlink.XfrmPolicy) bool
type stateFilter func(netlink.XfrmState) bool

func filterXFRMBySPI(policies []netlink.XfrmPolicy, states []netlink.XfrmState) ([]netlink.XfrmPolicy, []netlink.XfrmState) {
	return filterXFRMs(policies, states, func(pol netlink.XfrmPolicy) bool {
		return ipsec.GetSPIFromXfrmPolicy(&pol) == spiToFilter
	}, func(state netlink.XfrmState) bool {
		return state.Spi == int(spiToFilter)
	})
}

func filterXFRMByNodeID(policies []netlink.XfrmPolicy, states []netlink.XfrmState) ([]netlink.XfrmPolicy, []netlink.XfrmState) {
	return filterXFRMs(policies, states, func(pol netlink.XfrmPolicy) bool {
		return ipsec.GetNodeIDFromXfrmMark(pol.Mark) == nodeIDToFilter
	}, func(state netlink.XfrmState) bool {
		return ipsec.GetNodeIDFromXfrmMark(state.Mark) == nodeIDToFilter
	})
}

func filterXFRMs(policies []netlink.XfrmPolicy, states []netlink.XfrmState,
	filterPol policyFilter, filterState stateFilter) ([]netlink.XfrmPolicy, []netlink.XfrmState) {
	policiesToDel := []netlink.XfrmPolicy{}
	for _, pol := range policies {
		if filterPol(pol) {
			policiesToDel = append(policiesToDel, pol)
		}
	}

	statesToDel := []netlink.XfrmState{}
	for _, state := range states {
		if filterState(state) {
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
	encryptFlushCmd.Flags().Uint8Var(&spiToFilter, spiFlagName, 0, "Only delete states and policies with this SPI. If multiple filters are used, they all apply")
	encryptFlushCmd.Flags().StringVar(&nodeIDParam, nodeIDFlagName, "", "Only delete states and policies with this node ID. Decimal or hexadecimal (0x) format. If multiple filters are used, they all apply")
	CncryptCmd.AddCommand(encryptFlushCmd)
	command.AddOutputOption(encryptFlushCmd)
}
