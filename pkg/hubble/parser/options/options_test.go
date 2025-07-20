// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	opt := WithRedact(true, false, false, nil, nil)
	opts := Options{
		HubbleRedactSettings: HubbleRedactSettings{
			Enabled:            false,
			RedactHTTPQuery:    false,
			RedactHTTPUserInfo: false,
			RedactKafkaAPIKey:  false,
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
