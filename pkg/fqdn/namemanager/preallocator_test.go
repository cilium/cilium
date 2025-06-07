// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestLabelsForSelector(t *testing.T) {
	selFoo := api.FQDNSelector{
		MatchName: "foo.com",
	}

	require.Equal(t,
		[]labels.Labels{labels.NewLabelsFromSortedList("fqdn:foo.com;reserved:world")},
		labelsForSelector(true, false, selFoo),
	)

	require.Equal(t,
		[]labels.Labels{labels.NewLabelsFromSortedList("fqdn:foo.com;reserved:world")},
		labelsForSelector(false, true, selFoo),
	)

	require.Equal(t,
		[]labels.Labels{
			labels.NewLabelsFromSortedList("fqdn:foo.com;reserved:world-ipv4"),
			labels.NewLabelsFromSortedList("fqdn:foo.com;reserved:world-ipv6"),
		},
		labelsForSelector(true, true, selFoo),
	)

	selBar := api.FQDNSelector{
		MatchPattern: "*.cilium.io",
	}

	require.Equal(t,
		[]labels.Labels{labels.NewLabelsFromSortedList("fqdn:*.cilium.io;reserved:world")},
		labelsForSelector(true, false, selBar),
	)
}
