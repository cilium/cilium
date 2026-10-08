// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package provider

import (
	"context"
	"net/netip"

	"github.com/cilium/cilium/pkg/policy/api"
)

// RegisterTestDummyProvider registers a fake ExternalGroup provider
// only used for testing.
func RegisterTestDummyProvider() {
	providers[AWSProvider] = getDummyIPs
}

var DummmyIP1 = netip.MustParsePrefix("192.0.2.1/32")
var DummmyIP2 = netip.MustParsePrefix("192.0.2.2/32")

func getDummyIPs(_ context.Context, group *api.Groups) ([]netip.Prefix, error) {
	if group.AWS == nil {
		return nil, nil
	}

	// return a RFC5737 IP
	out := []netip.Prefix{}
	for _, sg := range group.AWS.SecurityGroupsNames {
		switch sg {
		case "dummy1":
			out = append(out, DummmyIP1)
		case "dummy2":
			out = append(out, DummmyIP2)
		}
	}
	return out, nil
}
