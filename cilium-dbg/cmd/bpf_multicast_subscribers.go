// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
)

const (
	allGroupsKW = "all"
	remoteKW    = "Remote Node"
	localKW     = "Local Endpoint"
)

var BpfMcastSubscriberCmd = &cobra.Command{
	Use:     "subscriber",
	Aliases: []string{"sub"},
	Short:   "Manage the multicast subscribers.",
}

func init() {
	BpfMcastSubscriberCmd.AddCommand(MulticastGroupSubscriberListCmd)
	command.AddOutputOption(MulticastGroupSubscriberListCmd)
	BpfMcastSubscriberCmd.AddCommand(MulticastGroupSubscriberAddCmd)
	BpfMcastSubscriberCmd.AddCommand(MulticastGroupSubscriberDelCmd)
}

var MulticastGroupSubscriberListCmd = &cobra.Command{
	Use:     "list < group | all >",
	Aliases: []string{"ls"},
	Short:   "List the multicast subscribers for the given group.",
	Long: `List the multicast subscribers for the given group. 
	To get the subscribers for all the groups, use 'cilium-dbg bpf multicast subscriber list all'.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multicast subscriber list")

		groupAddr, all, err := parseMulticastGroupSubscriberListArgs(args)
		if err != nil {
			Fatalf("invalid argument: %s", err)
		}

		groupV4Map, err := getMulticastGroupMap()
		if err != nil {
			Fatalf("Failed to get multicast bpf map: %s", err)
		}

		var groups []netip.Addr
		if all {
			groups, err = groupV4Map.List()
			if err != nil {
				Fatalf("Failed to list multicast groups: %s", err)
			}
		} else {
			groups = append(groups, groupAddr)
		}

		err = outputGroups(groups)
		if err != nil {
			Fatalf("Failed to list multicast subscribers: %s", err)
		}
	},
}

var MulticastGroupSubscriberAddCmd = &cobra.Command{
	Use:   "add <group> <subscriber-address>",
	Short: "Add a remote subscriber to the multicast group.",
	Long: `Add a remote subscriber to the multicast group.
Only remote subscribers are added via command line. Local subscribers will be automatically populated in the map based on IGMP messages.
Remote subscribers are typically other Cilium nodes, identified by internal IP of the node.
To add remote subscriber, following information is required:
- group: multicast group address to which subscriber is added.
- subscriber-address: subscriber IP address.
`,
	Example: `To add a remote node 10.100.0.1 to multicast group 229.0.0.1, use the following command:
cilium-dbg bpf multicast subscriber add 229.0.0.1 10.100.0.1
`,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multicast subscriber add")

		link, err := netlink.LinkByName(defaults.VxlanDevice)
		if err != nil {
			Fatalf("Failed to get cilium_vxlan device %q: %s", defaults.VxlanDevice, err)
		}

		groupAddr, subIP, err := parseMulticastGroupSubscriberArgs(args)
		if err != nil {
			Fatalf("invalid argument: %s", err)
		}

		subscriberMap, err := getMulticastSubscriberMap(groupAddr)
		if err != nil {
			Fatalf("Failed to get subscriber map for group %s: %s", groupAddr, err)
		}

		subscriber := &maps_multicast.SubscriberV4{
			SAddr:    subIP,
			Ifindex:  uint32(link.Attrs().Index),
			IsRemote: true,
		}

		if err := subscriberMap.Insert(subscriber); err != nil {
			Fatalf("Failed to add subscriber %s to multicast group %s: %s", subIP, groupAddr, err)
		}
	},
}

var MulticastGroupSubscriberDelCmd = &cobra.Command{
	Use:     "delete <group> <subscriber-address>",
	Aliases: []string{"del"},
	Short:   "Delete a subscriber from the multicast group.",
	Long: `Delete a subscriber from the given multicast group.
To delete remote subscriber, following information is required:
- group: multicast group address from which subscriber is deleted.
- subscriber-address: subscriber IP address
`,
	Example: `To delete a remote node 10.100.0.1 from multicast group 229.0.0.1, use the following command:
cilium-dbg bpf multicast subscriber delete 229.0.0.1 10.100.0.1
`,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multicast subscriber delete")

		groupAddr, subIP, err := parseMulticastGroupSubscriberArgs(args)
		if err != nil {
			Fatalf("invalid argument: %s\n", err)
		}

		subscriberMap, err := getMulticastSubscriberMap(groupAddr)
		if err != nil {
			Fatalf("Failed to get subscriber map for group %s: %s", groupAddr, err)
		}

		if err := subscriberMap.Delete(subIP); err != nil {
			Fatalf("Failed to delete subscriber %s from multicast group %s: %s", subIP, groupAddr, err)
		}
	},
}

// subscriberData is used to store the subscribers of a multicast group
type subscriberData struct {
	groupAddr   netip.Addr
	subscribers []*maps_multicast.SubscriberV4
}

func outputGroups(groupAddrs []netip.Addr) error {
	var allGroups []subscriberData

	for _, groupAddr := range groupAddrs {
		groupData := subscriberData{
			groupAddr: groupAddr,
		}

		subscriberMap, err := getMulticastSubscriberMap(groupAddr)
		if err != nil {
			return fmt.Errorf("failed to lookup multicast group %s: %w", groupAddr, err)
		}

		groupData.subscribers, err = subscriberMap.List()
		if err != nil {
			return fmt.Errorf("failed to list multicast subscribers for group %s: %w", groupAddr, err)
		}

		allGroups = append(allGroups, groupData)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(allGroups); err != nil {
			return fmt.Errorf("error getting output of map in %s: %w", command.OutputOptionString(), err)
		}
		return nil
	}

	printSubscriberList(allGroups)
	return nil
}

func printSubscriberList(subscribers []subscriberData) {
	sort.Slice(subscribers, func(i, j int) bool {
		return subscribers[i].groupAddr.Compare(subscribers[j].groupAddr) < 0
	})

	// sort subscribers in each group
	for _, group := range subscribers {
		sort.Slice(group.subscribers, func(i, j int) bool {
			return group.subscribers[i].SAddr.Compare(group.subscribers[j].SAddr) < 0
		})
	}

	w := tabwriter.NewWriter(os.Stdout, 16, 1, 0, ' ', 0)
	fmt.Fprintln(w, "Group\tSubscriber\tType\t")
	for _, subData := range subscribers {
		fmt.Fprintf(w, "%s\t", subData.groupAddr)
		for i, sub := range subData.subscribers {
			if i > 0 {
				// move by one tab to accommodate group address
				fmt.Fprintf(w, "\t")
			}
			fmt.Fprintf(w, "%s\t", sub.SAddr)
			fmt.Fprintf(w, "%s\t", getSubscriberType(sub.IsRemote))
			fmt.Fprintf(w, "\n")
		}

		if len(subData.subscribers) == 0 {
			fmt.Fprintf(w, "\n")
		}
	}
	w.Flush()
}

func getMulticastSubscriberMap(groupAddr netip.Addr) (maps_multicast.SubscriberV4Map, error) {
	groupV4Map, err := getMulticastGroupMap()
	if err != nil {
		return nil, err
	}

	subscriberMap, err := groupV4Map.Lookup(groupAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup multicast group %s: %w", groupAddr, err)
	}

	return subscriberMap, nil
}

func getSubscriberType(isRemote bool) string {
	if isRemote {
		return remoteKW
	}
	return localKW
}

func parseMulticastGroupSubscriberListArgs(args []string) (netip.Addr, bool, error) {
	if len(args) != 1 {
		return netip.Addr{}, false, fmt.Errorf("expected group address or 'all' as argument, got %d arguments", len(args))
	}

	if args[0] == allGroupsKW {
		return netip.Addr{}, true, nil
	}

	addr, err := parseMulticastGroupArgs(args)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("invalid group address: %w", err)
	}

	return addr, false, nil
}

func parseMulticastGroupSubscriberArgs(args []string) (groupAddr, subscriberAddr netip.Addr, err error) {
	if len(args) != 2 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("expected exactly two arguments, group address and subscriber address, got %d arguments", len(args))
	}

	groupAddr, err = parseMulticastGroupArgs(args[:1])
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid group address: %w", err)
	}

	subscriberAddr, err = netip.ParseAddr(args[1])
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid subscriber address: %s", err)
	}

	return groupAddr, subscriberAddr, nil
}
