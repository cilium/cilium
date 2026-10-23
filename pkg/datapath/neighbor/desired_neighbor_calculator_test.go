// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ netlinkFuncs = (*fakeNetlinkFuncs)(nil)

// fakeNetlinkFuncs returns a fixed result for every route lookup.
type fakeNetlinkFuncs struct {
	routes []netlink.Route
	err    error
}

func (f *fakeNetlinkFuncs) RouteGetWithOptions(net.IP, *netlink.RouteGetOptions) ([]netlink.Route, error) {
	return f.routes, f.err
}

func (f *fakeNetlinkFuncs) NeighSet(*netlink.Neigh) error { return nil }

func (f *fakeNetlinkFuncs) NeighDel(*netlink.Neigh) error { return nil }

func TestGetNextHopIP(t *testing.T) {
	const ifindex = 2

	tests := []struct {
		name        string
		ip          string
		routes      []netlink.Route
		routeErr    error
		wantNextHop string
		wantErr     error
	}{
		{
			name: "local IPv4 address",
			ip:   "192.168.0.2",
			routes: []netlink.Route{{
				LinkIndex: ifindex,
				Type:      unix.RTN_LOCAL,
				Scope:     netlink.SCOPE_HOST,
			}},
			wantErr: errIPIsLocal,
		},
		{
			name: "local IPv6 address",
			ip:   "ff::aa01",
			routes: []netlink.Route{{
				LinkIndex: ifindex,
				Type:      unix.RTN_LOCAL,
			}},
			wantErr: errIPIsLocal,
		},
		{
			name: "directly connected IPv4",
			ip:   "192.168.0.3",
			routes: []netlink.Route{{
				LinkIndex: ifindex,
				Type:      unix.RTN_UNICAST,
				Scope:     netlink.SCOPE_LINK,
			}},
			wantNextHop: "192.168.0.3",
		},
		{
			name:     "unreachable",
			ip:       "100.0.0.123",
			routeErr: unix.EHOSTUNREACH,
			wantErr:  errNodeIPNotRoutable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &desiredNeighborCalculator{
				desiredNeighborCalculatorParams: desiredNeighborCalculatorParams{
					FuncsGetter: &netlinkFuncsGetter{
						funcs: &fakeNetlinkFuncs{routes: tt.routes, err: tt.routeErr},
					},
					Metrics: NewNeighborMetrics(),
				},
			}

			nextHop, err := c.getNextHopIP(netip.MustParseAddr(tt.ip), ifindex)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.False(t, nextHop.IsValid())
				return
			}

			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(tt.wantNextHop), nextHop)
		})
	}
}
