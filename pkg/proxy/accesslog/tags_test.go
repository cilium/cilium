// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package accesslog

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
)

type endpointInfoRegistryFunc func(*EndpointInfo, netip.Addr)

func (f endpointInfoRegistryFunc) FillEndpointInfo(_ context.Context, info *EndpointInfo, addr netip.Addr) {
	f(info, addr)
}

func TestAddressingIdentityProvided(t *testing.T) {
	sourceIP := netip.MustParseAddr("192.0.2.10")
	destinationIP := netip.MustParseAddr("192.0.2.20")

	tests := []struct {
		name                    string
		addressing              AddressingInfo
		wantSourceIdentity      uint64
		wantDestinationIdentity uint64
		wantSourceProvided      bool
		wantDestinationProvided bool
		fillSourceIdentity      uint64
		fillDestinationIdentity uint64
	}{
		{
			name: "security identity pointers",
			addressing: AddressingInfo{
				SrcSecIdentity: &identity.Identity{ID: 101},
				SrcIdentity:    901,
				DstSecIdentity: &identity.Identity{ID: 202},
				DstIdentity:    902,
			},
			wantSourceIdentity:      101,
			wantDestinationIdentity: 202,
			wantSourceProvided:      true,
			wantDestinationProvided: true,
		},
		{
			name: "numeric identity fallback",
			addressing: AddressingInfo{
				SrcIdentity: 303,
				DstIdentity: 404,
			},
			wantSourceIdentity:      303,
			wantDestinationIdentity: 404,
			wantSourceProvided:      true,
			wantDestinationProvided: true,
		},
		{
			name: "unknown pointer overrides numeric fallback",
			addressing: AddressingInfo{
				SrcSecIdentity: &identity.Identity{ID: identity.IdentityUnknown},
				SrcIdentity:    505,
				DstSecIdentity: &identity.Identity{ID: identity.IdentityUnknown},
				DstIdentity:    606,
			},
			wantSourceIdentity:      7001,
			wantDestinationIdentity: 7002,
			wantSourceProvided:      false,
			wantDestinationProvided: false,
			fillSourceIdentity:      7001,
			fillDestinationIdentity: 7002,
		},
		{
			name: "unknown numeric identity remains unprovided after userspace fill",
			addressing: AddressingInfo{
				SrcIdentity: identity.IdentityUnknown,
				DstIdentity: identity.IdentityUnknown,
			},
			wantSourceIdentity:      8001,
			wantDestinationIdentity: 8002,
			wantSourceProvided:      false,
			wantDestinationProvided: false,
			fillSourceIdentity:      8001,
			fillDestinationIdentity: 8002,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addressing := tt.addressing
			addressing.SrcIPPort = netip.AddrPortFrom(sourceIP, 1234).String()
			addressing.DstIPPort = netip.AddrPortFrom(destinationIP, 4321).String()

			sourceFillCalled := false
			destinationFillCalled := false
			registry := endpointInfoRegistryFunc(func(info *EndpointInfo, addr netip.Addr) {
				switch addr {
				case sourceIP:
					sourceFillCalled = true
					require.Equal(t, tt.wantSourceProvided, info.SecurityIdentityProvided,
						"source provenance must be set from the selected original identity before userspace fill")
					if tt.fillSourceIdentity != 0 {
						require.Zero(t, info.Identity, "an unknown pointer must override a numeric fallback")
						info.Identity = tt.fillSourceIdentity
					}
				case destinationIP:
					destinationFillCalled = true
					require.Equal(t, tt.wantDestinationProvided, info.SecurityIdentityProvided,
						"destination provenance must be set from the selected original identity before userspace fill")
					if tt.fillDestinationIdentity != 0 {
						require.Zero(t, info.Identity, "an unknown pointer must override a numeric fallback")
						info.Identity = tt.fillDestinationIdentity
					}
				default:
					t.Fatalf("unexpected endpoint address %s", addr)
				}
			})

			record := LogRecord{
				SourceEndpoint:      EndpointInfo{SecurityIdentityProvided: true},
				DestinationEndpoint: EndpointInfo{SecurityIdentityProvided: true},
			}
			LogTags.Addressing(t.Context(), addressing)(&record, registry)

			require.True(t, sourceFillCalled)
			require.True(t, destinationFillCalled)
			require.Equal(t, tt.wantSourceIdentity, record.SourceEndpoint.Identity)
			require.Equal(t, tt.wantDestinationIdentity, record.DestinationEndpoint.Identity)
			require.Equal(t, tt.wantSourceProvided, record.SourceEndpoint.SecurityIdentityProvided)
			require.Equal(t, tt.wantDestinationProvided, record.DestinationEndpoint.SecurityIdentityProvided)
		})
	}
}
