// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package config provides BGP configuration logic.
package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	config, err := Parse(strings.NewReader(yaml))
	require.NoError(t, err)
	require.NotNil(t, config)

	config, err = Parse(strings.NewReader(json))
	require.NoError(t, err)
	require.NotNil(t, config)

	config, err = Parse(strings.NewReader(`{"json":"random"}`))
	// Usually we use ErrorMatches here, but the error string has newlines
	// which makes the regex matching fail.
	require.True(t, strings.HasPrefix(err.Error(), "failed to parse MetalLB config:"))
	require.Nil(t, config)
}

const (
	yaml = `---
peers:
  - peer-address: 172.19.0.5
    peer-asn: 64512
    my-asn: 64512
address-pools:
  - name: default
    protocol: bgp
    addresses:
      - 192.168.1.150/29
`
	json = `{"peers":[{"peer-address":"172.19.0.5","peer-asn":64512,"my-asn":64512}],"address-pools":[{"name":"default","protocol":"bgp","addresses":["192.168.1.150/29"]}]}`
)
