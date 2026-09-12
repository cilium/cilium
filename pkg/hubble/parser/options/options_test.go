// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestExcludeHttpHeaders(t *testing.T) {
	opt := WithExcludeHttpHeaders([]string{"X-Allow", "Content-Type"}, nil)
	opts := Options{}
	opt(&opts)
	// Header names are normalised to lowercase.
	assert.Equal(t, map[string]struct{}{"x-allow": {}, "content-type": {}}, opts.ExcludeHttpHeaders.Allow)
	assert.Empty(t, opts.ExcludeHttpHeaders.Deny)

	opt = WithExcludeHttpHeaders(nil, []string{"Authorization"})
	opts = Options{}
	opt(&opts)
	assert.Empty(t, opts.ExcludeHttpHeaders.Allow)
	assert.Equal(t, map[string]struct{}{"authorization": {}}, opts.ExcludeHttpHeaders.Deny)
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
