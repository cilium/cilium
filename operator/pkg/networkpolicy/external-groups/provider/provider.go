// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package provider

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	AWSProvider = "AWS" // AWS provider key
)

var (
	providers = map[string]GroupProviderFunc{} // map with the list of providers to callback to retrieve info from.
)

type GroupProviderFunc func(context.Context, *api.Groups) ([]netip.Prefix, error)

func Enabled() bool {
	return len(providers) > 0
}

// GetCidrSet will return the CIDRRule for the rule using the callbacks that
// are register in the platform.
func GetCidrSet(ctx context.Context, group *api.Groups) ([]netip.Prefix, error) {
	var addrs []netip.Prefix
	if len(providers) == 0 {
		return nil, fmt.Errorf("No registered Group providers")
	}

	for provider, getIPsFunc := range providers {
		// Get per  provider CIDRSet
		a, err := getIPsFunc(ctx, group)
		if err != nil {
			return nil, fmt.Errorf(
				"Cannot retrieve data from %s provider: %w",
				provider, err)
		}
		addrs = append(addrs, a...)
	}

	slices.SortFunc(addrs, netip.Prefix.Compare)

	return slices.Compact(addrs), nil
}
