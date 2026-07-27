// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

func TestLabelsForSelector(t *testing.T) {
	selFoo := api.FQDNSelector{
		MatchName: "foo.com",
	}

	require.Equal(t,
		[]labels.Labels{testidentity.FQDNLabelsSingleStack},
		labelsForSelector(true, false, selFoo),
	)

	require.Equal(t,
		[]labels.Labels{testidentity.FQDNLabelsSingleStack},
		labelsForSelector(false, true, selFoo),
	)

	require.Equal(t,
		[]labels.Labels{
			testidentity.FQDNLabelsV4,
			testidentity.FQDNLabelsV6,
		},
		labelsForSelector(true, true, selFoo),
	)
}
