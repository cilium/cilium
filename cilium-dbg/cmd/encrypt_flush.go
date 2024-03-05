// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/common/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/maps/nodemap"
)

const (
	spiFlagName    = "spi"
	nodeIDFlagName = "node-id"
	staleFlagName  = "stale"
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
	cleanStale     bool
)

func runXFRMFlush() {
	if spiToFilter == 0 && nodeIDParam == "" && !cleanStale {
		flushEverything()
		return
	}

	if cleanStale && (spiToFilter != 0 || nodeIDParam != "") {
		Fatalf("--%s cannot be combined with other flags except for --%s", staleFlagName, forceFlagName)
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
	if cleanStale {
		policies, states = filterStaleXFRMs(policies, states)
	}

	confirmationMsg := ""
	if len(policies) == nbPolicies || len(states) == nbStates {
		confirmationMsg = "Running this command will delete all XFRM states and/or policies. " +
			"It will lead to transient connectivity disruption and plain-text pod-to-pod traffic."
	} else if cleanStale {
		if len(policies) == 0 && len(states) == 0 {
			fmt.Printf("No stale XFRM states or policies found.")
			return
		}
		confirmationMsg = fmt.Sprintf("This command will delete %d XFRM policies and %d XFRM states.",
			len(policies), len(states))
	}
	if confirmationMsg != "" && !confirmXFRMCleanup(confirmationMsg) {
		return
	}

	nbDeleted := len(states)
	for _, state := range states {
		if err := netlink.XfrmStateDel(&state); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to delete XFRM state: %s", err)
			nbDeleted--
		}
	}
	fmt.Printf("Deleted %d XFRM states.\n", nbDeleted)
	nbDeleted = len(policies)
	for _, pol := range policies {
		if err := netlink.XfrmPolicyDel(&pol); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to delete XFRM policy: %s", err)
			nbDeleted--
		}
	}
	fmt.Printf("Deleted %d XFRM policies.\n", nbDeleted)
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

func filterStaleXFRMs(policies []netlink.XfrmPolicy, states []netlink.XfrmState) ([]netlink.XfrmPolicy, []netlink.XfrmState) {
	bpfNodeIDs := map[uint16]bool{}
	parse := func(key *nodemap.NodeKey, val *nodemap.NodeValue) {
		bpfNodeIDs[val.NodeID] = true
	}
	nodeMap, err := nodemap.LoadNodeMap()
	if err != nil {
		Fatalf("Cannot load node bpf map: %s", err)
	}
	if err := nodeMap.IterateWithCallback(parse); err != nil {
		Fatalf("Error dumping contents of the node ID map: %s\n", err)
	}

	policiesToDel := []netlink.XfrmPolicy{}
	for _, pol := range policies {
		nodeID := ipsec.GetNodeIDFromXfrmMark(pol.Mark)
		if nodeID == 0 {
			continue
		}
		if _, found := bpfNodeIDs[nodeID]; !found {
			policiesToDel = append(policiesToDel, pol)
		}
	}

	statesToDel := []netlink.XfrmState{}
	for _, state := range states {
		nodeID := ipsec.GetNodeIDFromXfrmMark(state.Mark)
		if nodeID == 0 {
			continue
		}
		if _, found := bpfNodeIDs[nodeID]; !found {
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
	encryptFlushCmd.Flags().BoolVar(&cleanStale, staleFlagName, false, "Delete stale states and policies based on the current node ID map content")
	CncryptCmd.AddCommand(encryptFlushCmd)
	command.AddOutputOption(encryptFlushCmd)
}
