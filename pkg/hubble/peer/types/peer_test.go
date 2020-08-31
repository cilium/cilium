// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package types

import (
	"net"
	"testing"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/defaults"

	"github.com/stretchr/testify/assert"
)

func TestFromChangeNotification(t *testing.T) {
	tests := []struct {
		name string
		arg  *peerpb.ChangeNotification
		want *Peer
	}{
		{
			name: "nil",
			arg:  nil,
			want: (*Peer)(nil),
		}, {
			name: "without address",
			arg: &peerpb.ChangeNotification{
				Name: "name",
			},
			want: &Peer{
				Name:    "name",
				Address: nil,
			},
		}, {
			name: "with IPv4 address but without port",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "192.0.2.1",
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("192.0.2.1"),
					Port: defaults.ServerPort,
				},
			},
		}, {
			name: "with an IPv4 address and port",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "192.0.2.1:4000",
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("192.0.2.1"),
					Port: 4000,
				},
			},
		}, {
			name: "with an IPv4 address and a bad port",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "192.0.2.1:4x",
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("192.0.2.1"),
					Port: defaults.ServerPort,
				},
			},
		}, {
			name: "with an IPv6 address but without port",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "2001:db8::68",
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("2001:db8::68"),
					Port: defaults.ServerPort,
				},
			},
		}, {
			name: "with an IPv6 address and port",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "[2001:db8::68]:4000",
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("2001:db8::68"),
					Port: 4000,
				},
			},
		}, {
			name: "with an IPv6 address and a bad port",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "[2001:db8::68]:4x",
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("2001:db8::68"),
					Port: defaults.ServerPort,
				},
			},
		}, {
			name: "with a unix domain socket",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "unix:///var/run/hubble.sock",
			},
			want: &Peer{
				Name: "name",
				Address: &net.UnixAddr{
					Name: "unix:///var/run/hubble.sock",
					Net:  "unix",
				},
			},
		}, {
			name: "with a unix domain socket without prefix",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "/var/run/hubble.sock",
			},
			want: &Peer{
				Name: "name",
				Address: &net.UnixAddr{
					Name: "/var/run/hubble.sock",
					Net:  "unix",
				},
			},
		}, {
			name: "with an IPv4 address and port and TLS enabled",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "192.0.2.1:4000",
				Tls:     &peerpb.TLS{},
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("192.0.2.1"),
					Port: 4000,
				},
				TLSEnabled: true,
			},
		}, {
			name: "with an IPv4 address and port and TLS enabled with server name",
			arg: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "192.0.2.1:4000",
				Tls: &peerpb.TLS{
					ServerName: "name.default.hubble-grpc.cilium.io",
				},
			},
			want: &Peer{
				Name: "name",
				Address: &net.TCPAddr{
					IP:   net.ParseIP("192.0.2.1"),
					Port: 4000,
				},
				TLSEnabled:    true,
				TLSServerName: "name.default.hubble-grpc.cilium.io",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromChangeNotification(tt.arg)
			assert.Equal(t, tt.want, got)
		})
	}
}
