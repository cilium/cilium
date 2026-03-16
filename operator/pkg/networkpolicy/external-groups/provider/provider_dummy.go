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

var DummmyIP1 = netip.MustParseAddr("192.0.2.1")
var DummmyIP2 = netip.MustParseAddr("192.0.2.2")

func getDummyIPs(_ context.Context, group *api.Groups) ([]netip.Addr, error) {
	if group.AWS == nil {
		return nil, nil
	}

	// return a RFC5737 IP
	out := []netip.Addr{}
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
