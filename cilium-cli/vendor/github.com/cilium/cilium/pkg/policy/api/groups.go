// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	AWSProvider = "AWS" // AWS provider key
)

var (
	providers lock.Map[string, GroupProviderFunc] // map with the list of providers to callback to retrieve info from.
)

// GroupProviderFunc is a func that need to be register to be able to
// register a new provider in the platform.
type GroupProviderFunc func(context.Context, *ToGroups) ([]netip.Addr, error)

// ToGroups structure to store all kinds of new integrations that needs a new
// derivative policy.
type ToGroups struct {
	AWS *AWSGroup `json:"aws,omitempty"`
}

// AWSGroup is an structure that can be used to whitelisting information from AWS integration
type AWSGroup struct {
	Labels              map[string]string `json:"labels,omitempty"`
	SecurityGroupsIds   []string          `json:"securityGroupsIds,omitempty"`
	SecurityGroupsNames []string          `json:"securityGroupsNames,omitempty"`
	Region              string            `json:"region,omitempty"`
}

// RegisterToGroupsProvider it will register a new callback that will be used
// when a new ToGroups rule is added.
func RegisterToGroupsProvider(providerName string, callback GroupProviderFunc) {
	providers.Store(providerName, callback)
}

// GetCidrSet will return the CIDRRule for the rule using the callbacks that
// are register in the platform.
func (group *ToGroups) GetCidrSet(ctx context.Context) ([]CIDRRule, error) {
	var addrs []netip.Addr
	// Get per  provider CIDRSet
	if group.AWS != nil {
		callback, ok := providers.Load(AWSProvider)
		if !ok {
			return nil, fmt.Errorf("Provider %s is not registered", AWSProvider)
		}
		awsAddrs, err := callback(ctx, group)
		if err != nil {
			return nil, fmt.Errorf(
				"Cannot retrieve data from %s provider: %s",
				AWSProvider, err)
		}
		addrs = append(addrs, awsAddrs...)
	}

	resultAddrs := ip.KeepUniqueAddrs(addrs)
	return addrsToCIDRRules(resultAddrs), nil
}
