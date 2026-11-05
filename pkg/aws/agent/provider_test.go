// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestProviderInitializeVPCCIDRFailure(t *testing.T) {
	// VPC CIDRs that cannot be determined must fail loudly at initialization:
	// they drive masquerade exclusion, so proceeding without them would
	// silently SNAT cross-node pod traffic.
	newTestProvider := func(t *testing.T, stub *stubMetadata) *provider {
		return &provider{
			params: providerParams{
				Logger:         hivetest.Logger(t),
				LocalNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
				Conf:           &option.DaemonConfig{EnableIPv4: true},
				Metadata:       stub.instanceMetadata(),
			},
		}
	}

	t.Run("the IMDS is unreachable", func(t *testing.T) {
		p := newTestProvider(t, &stubMetadata{vpcErr: errors.New("IMDS unreachable")})
		_, err := p.Initialize(t.Context())
		require.ErrorContains(t, err, "IMDS unreachable")
	})

	t.Run("the IMDS reports no CIDR", func(t *testing.T) {
		p := newTestProvider(t, &stubMetadata{})
		_, err := p.Initialize(t.Context())
		require.ErrorContains(t, err, "no IPv4 VPC CIDRs")
	})

	t.Run("the configured native routing CIDR overlaps no VPC CIDR", func(t *testing.T) {
		p := newTestProvider(t, &stubMetadata{
			vpcCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
		})
		p.params.Conf = &option.DaemonConfig{
			EnableIPv4:            true,
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("192.168.0.0/16"),
		}
		_, err := p.Initialize(t.Context())
		require.ErrorContains(t, err, "overlaps none of the VPC CIDRs")
	})
}
