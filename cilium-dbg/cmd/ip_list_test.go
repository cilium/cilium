// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	iputil "github.com/cilium/cilium/pkg/ip"
)

func TestSortIPListEntries(t *testing.T) {
	var entries []*models.IPListEntry
	for _, s := range []string{"f00d::/64", "11.0.0.0/8", "10.0.0.1/32", "10.0.0.0/8"} {
		entries = append(entries, &models.IPListEntry{
			Cidr: iputil.PrefixFrom(netip.MustParsePrefix(s)),
		})
	}

	sortIPListEntries(entries)

	var got []string
	for _, e := range entries {
		got = append(got, e.Cidr.String())
	}
	require.Equal(t, []string{"10.0.0.0/8", "10.0.0.1/32", "11.0.0.0/8", "f00d::/64"}, got)
}

func TestFormatIPListEntries(t *testing.T) {
	entries := []*models.IPListEntry{
		{
			Cidr:       iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
			HostIP:     iputil.AddrFrom(netip.MustParseAddr("192.168.1.12")),
			Identity:   new(int64(12345)),
			EncryptKey: 7,
			Metadata:   &models.IPListEntryMetadata{Source: "kubernetes", Name: "pod", Namespace: "default"},
		},
		{
			Cidr:     iputil.PrefixFrom(netip.MustParsePrefix("fd00::1/128")),
			HostIP:   iputil.AddrFrom(netip.MustParseAddr("fd00::12")),
			Identity: new(int64(23456)),
		},
		{
			Cidr:     iputil.PrefixFrom(netip.MustParsePrefix("0.0.0.0/0")),
			Identity: new(int64(2)),
		},
	}
	output := formatIPListEntries(entries)

	for _, tt := range []struct {
		name     string
		jsonPath string
		want     string
	}{
		{
			name:     "non-empty host addresses",
			jsonPath: `{[?(@.hostIP!="")].identity}`,
			want:     "12345 23456",
		},
		{
			name:     "empty host addresses",
			jsonPath: `{[?(@.hostIP=="")].identity}`,
			want:     "2",
		},
		{
			name:     "IPv4 host address",
			jsonPath: `{[?(@.hostIP=="192.168.1.12")].identity}`,
			want:     "12345",
		},
		{
			name:     "IPv6 host address",
			jsonPath: `{[?(@.hostIP=="fd00::12")].identity}`,
			want:     "23456",
		},
		{
			name:     "CIDR",
			jsonPath: `{[?(@.cidr=="10.0.0.1/32")].identity}`,
			want:     "12345",
		},
		{
			name:     "integer encryption key",
			jsonPath: `{[?(@.encryptKey==7)].identity}`,
			want:     "12345",
		},
		{
			name:     "zero encryption key",
			jsonPath: `{[?(@.encryptKey==0)].identity}`,
			want:     "23456 2",
		},
		{
			name:     "zero encryption key output",
			jsonPath: `{[1].encryptKey}`,
			want:     "0",
		},
		{
			name:     "address output",
			jsonPath: `{[0].hostIP}`,
			want:     "192.168.1.12",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := command.DumpJSONToString(output, tt.jsonPath)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	for _, tt := range []struct {
		name    string
		marshal func(any) ([]byte, error)
	}{
		{name: "JSON output unchanged", marshal: json.Marshal},
		{name: "YAML output unchanged", marshal: yaml.Marshal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want, err := tt.marshal(entries)
			require.NoError(t, err)
			got, err := tt.marshal(output)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}
