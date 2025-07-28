// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/stretchr/testify/require"
)

func TestParseURL(t *testing.T) {
	logs := []*cilium.HttpLogEntry{
		{Scheme: "http", Host: "foo", Path: "/foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "/foo"},
	}

	for _, l := range logs {
		u := ParseURL(l.Scheme, l.Host, l.Path)
		require.Equal(t, "http", u.Scheme)
		require.Equal(t, "foo", u.Host)
		require.Equal(t, "/foo", u.Path)
	}
}
