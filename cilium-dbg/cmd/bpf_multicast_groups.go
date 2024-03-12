// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
)

var BpfMcastGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage the multicast groups.",
}

func init() {
	BpfMcastGroupCmd.AddCommand(MulticastGroupListCmd)
	command.AddOutputOption(MulticastGroupListCmd)
	BpfMcastGroupCmd.AddCommand(MulticastGroupAddCmd)
	BpfMcastGroupCmd.AddCommand(MulticastGroupDelCmd)
}

var MulticastGroupListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List the multicast groups.",
	Long:    "List the multicast groups configured on the node.",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multicast group list")

		groupV4Map, err := getMulticastGroupMap()
		if err != nil {
			Fatalf("failed to get multicast bpf map: %s", err)
		}

		groups, err := groupV4Map.List()
		if err != nil {
			Fatalf("Error listing multicast groups: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(groups); err != nil {
				Fatalf("error getting output of map in %s: %s", command.OutputOptionString(), err)
			}
			return
		}
		printGroupList(groups)
	},
}

func printGroupList(groups []netip.Addr) {
	// sort groups by address
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Compare(groups[j]) < 0
	})

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Group Address")
	for _, group := range groups {
		fmt.Fprintf(w, "%s\n", group.String())
	}
	w.Flush()
}

var MulticastGroupAddCmd = &cobra.Command{
	Use:   "add <group>",
	Short: "Add a multicast group.",
	Long:  "Add a multicast group to the node.",
	Example: `The following command adds group 229.0.0.1 to BPF multicast map of the node:
cilium-dbg bpf multicast group add 229.0.0.1`,

	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf multicast group add")

		group, err := parseMulticastGroupArgs(args)
		if err != nil {
			Fatalf("Invalid arguments: %s", err)
		}

		groupV4Map, err := getMulticastGroupMap()
		if err != nil {
			Fatalf("failed to get multicast bpf map: %s", err)
		}

		err = groupV4Map.Insert(group)
		if err != nil {
			Fatalf("Error adding multicast group: %s", err)
		}
	},
}

var MulticastGroupDelCmd = &cobra.Command{
	Use:     "delete <group>",
	Aliases: []string{"del"},
	Short:   "Delete a multicast group.",
	Long:    "Delete a multicast group from the node.",
	Example: `The following command deletes group 229.0.0.1 from BPF multicast map of the node:
cilium-dbg bpf multicast group delete 229.0.0.1`,

	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf multicast group delete")

		group, err := parseMulticastGroupArgs(args)
		if err != nil {
			Fatalf("Invalid arguments: %s", err)
		}

		groupV4Map, err := getMulticastGroupMap()
		if err != nil {
			Fatalf("failed to get multicast bpf map: %s", err)
		}

		err = groupV4Map.Delete(group)
		if err != nil {
			Fatalf("Error deleting multicast group: %s", err)
		}
	},
}

func getMulticastGroupMap() (*maps_multicast.GroupV4OuterMap, error) {
	groupV4Map, err := maps_multicast.OpenGroupV4OuterMap(maps_multicast.GroupOuter4MapName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("multicast not enabled")
		}
		return nil, fmt.Errorf("cannot open multicast bpf maps: %w", err)
	}

	return groupV4Map, nil
}

func parseMulticastGroupArgs(args []string) (netip.Addr, error) {
	if len(args) != 1 {
		return netip.Addr{}, fmt.Errorf("expecting group IP as argument, got %d arguments", len(args))
	}

	group, err := netip.ParseAddr(args[0])
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address format: %w", err)
	}

	// check group is multicast and ipv4 address
	if !group.Is4() || !group.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("invalid multicast IP: %s", group.String())
	}

	return group, nil
}
