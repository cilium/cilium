// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package options

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
)

type fakeNodeLabelsGetter struct{}

func (*fakeNodeLabelsGetter) GetNodeLabels(netip.Addr, getters.NodeClusterHint) []string {
	return nil
}

func TestWithNodeLabelsGetter(t *testing.T) {
	var opts Options
	require.Nil(t, opts.NodeLabelsGetter, "the zero value must preserve parser behavior")

	getter := &fakeNodeLabelsGetter{}
	WithNodeLabelsGetter(getter)(&opts)
	require.Same(t, getter, opts.NodeLabelsGetter)

	WithNodeLabelsGetter(nil)(&opts)
	require.Nil(t, opts.NodeLabelsGetter)
}

func TestRedact(t *testing.T) {
	opt := WithRedact(true, false, nil, nil)
	opts := Options{
		HubbleRedactSettings: HubbleRedactSettings{
			Enabled:            false,
			RedactHTTPQuery:    false,
			RedactHTTPUserInfo: false,
			RedactHttpHeaders: HttpHeadersList{
				Allow: map[string]struct{}{},
				Deny:  map[string]struct{}{"tracecontent": {}},
			},
		},
	}
	opt(&opts)
	assert.True(t, opts.HubbleRedactSettings.Enabled)
	assert.True(t, opts.HubbleRedactSettings.RedactHTTPQuery)
}

func TestEnableNetworkPolicyCorrelation(t *testing.T) {
	opt := WithNetworkPolicyCorrelation(true)
	opts := Options{EnableNetworkPolicyCorrelation: false}
	opt(&opts)
	assert.True(t, opts.EnableNetworkPolicyCorrelation)
}

func TestSkipUnknownCGroupIDs(t *testing.T) {
	opt := WithSkipUnknownCGroupIDs(false)
	opts := Options{SkipUnknownCGroupIDs: true}
	opt(&opts)
	assert.False(t, opts.SkipUnknownCGroupIDs)
}
