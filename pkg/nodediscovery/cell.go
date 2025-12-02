// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
)

// The node discovery cell provides the local node configuration and node discovery
// which communicate changes in local node information to the API server or KVStore.
var Cell = cell.Module(
	"nodediscovery",
	"Communicate changes in local node information to the API server or KVStore",

	// Node discovery communicates changes in local node information to the API server or KVStore
	cell.Provide(NewNodeDiscovery),

	// Register node discovery to the fence to ensure that we wait for node
	// synchronization from the kvstore (when enabled) before endpoint regen,
	// as nodes also contribute entries to the ipcache map, most notably about
	// the remote node IPs.
	cell.Invoke(func(nd *NodeDiscovery, fence regeneration.Fence) {
		fence.Add("kvstore-nodes", nd.WaitForKVStoreSync)
	}),
	cell.Config(defaultConfig),
)

var defaultConfig = config{
	IPAMMinAllocate: 0,
	IPAMPreAllocate: 0,

	ENIFirstInterfaceIndex:     defaults.ENIFirstInterfaceIndex,
	ENISubnetIDs:               []string{},
	ENISubnetTags:              map[string]string{},
	ENISecurityGroups:          []string{},
	ENISecurityGroupTags:       map[string]string{},
	ENIExcludeInterfaceTags:    map[string]string{},
	ENIUsePrimaryAddress:       defaults.UseENIPrimaryAddress,
	ENIDisablePrefixDelegation: defaults.ENIDisableNodeLevelPD,
	ENIDeleteOnTermination:     defaults.ENIDeleteOnTermination,
}

type config struct {
	IPAMMinAllocate int
	IPAMPreAllocate int

	ENIFirstInterfaceIndex     int
	ENISubnetIDs               []string
	ENISubnetTags              map[string]string
	ENISecurityGroups          []string
	ENISecurityGroupTags       map[string]string
	ENIExcludeInterfaceTags    map[string]string
	ENIUsePrimaryAddress       bool
	ENIDisablePrefixDelegation bool
	ENIDeleteOnTermination     bool
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Int("ipam-min-allocate", c.IPAMMinAllocate, "Minimum number of IPs that must be allocated when the node is first bootstrapped at the node level")
	flags.Int("ipam-pre-allocate", c.IPAMPreAllocate, "Number of IP addresses that must be available for allocation in the IPAMspec at the node level")

	flags.Int("eni-first-interface-index", c.ENIFirstInterfaceIndex, "Index of the first ENI to use for IP allocation at the node level")
	flags.StringToString("eni-exclude-interface-tags", c.ENIExcludeInterfaceTags, "List of tags to use when excluding ENIs for Cilium IP allocation")
	flags.StringSlice("eni-subnet-ids", c.ENISubnetIDs, "List of subnet ids to use when evaluating what AWS subnets to use for ENI and IP allocation at the node level")
	flags.StringToString("eni-subnet-tags", c.ENISubnetTags, "List of tags to use when evaluating what AWS subnets to use for ENI and IP allocation at the node level")
	flags.StringSlice("eni-security-groups", c.ENISecurityGroups, "List of security groups to attach to any ENI that is created and attached to the instance at the node level")
	flags.StringToString("eni-security-group-tags", c.ENISecurityGroupTags, "List of tags to use when evaluating what AWS security groups to use for the ENI at the node level")
	flags.Bool("eni-use-primary-address", c.ENIUsePrimaryAddress, "Whether an ENI's primary address should be available for allocations on the node at the node level")
	flags.Bool("eni-disable-prefix-delegation", c.ENIDisablePrefixDelegation, "Whether ENI prefix delegation should be disabled on this node at the node level")
	flags.Bool("eni-delete-on-termination", c.ENIDeleteOnTermination, "Whether the ENI should be deleted when the associated instance is terminated at the node level")
}
