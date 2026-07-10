// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restore

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRuleIPOrCIDR(t *testing.T) {
	rule, err := ParseRuleIPOrCIDR("172.18.0.1")
	assert.NoError(t, err)
	assert.True(t, rule.IsAddr())
	assert.Equal(t, rule.Addr(), netip.MustParseAddr("172.18.0.1"))

	rule, err = ParseRuleIPOrCIDR("172.18.0.1/32")
	assert.NoError(t, err)
	assert.False(t, rule.IsAddr())
	assert.Equal(t, netip.Prefix(rule), netip.MustParsePrefix("172.18.0.1/32"))

	rule, err = ParseRuleIPOrCIDR("172.18.0.0/16")
	assert.NoError(t, err)
	assert.False(t, rule.IsAddr())
	assert.Equal(t, netip.Prefix(rule), netip.MustParsePrefix("172.18.0.0/16"))

	rule, err = ParseRuleIPOrCIDR("172.18.0.2@0")
	assert.NoError(t, err)
	assert.True(t, rule.IsAddr())
	assert.Equal(t, rule.Addr(), netip.MustParseAddr("172.18.0.2"))

	rule, err = ParseRuleIPOrCIDR("172.18.0.2/32@0")
	assert.NoError(t, err)
	assert.False(t, rule.IsAddr())
	assert.Equal(t, netip.Prefix(rule), netip.MustParsePrefix("172.18.0.2/32"))

	rule, err = ParseRuleIPOrCIDR("172.18.0.0/16@0")
	assert.NoError(t, err)
	assert.False(t, rule.IsAddr())
	assert.Equal(t, netip.Prefix(rule), netip.MustParsePrefix("172.18.0.0/16"))

	_, err = ParseRuleIPOrCIDR("172.18.0.0/16@")
	assert.Error(t, err)

	_, err = ParseRuleIPOrCIDR("172.18.0.0/16@wrong")
	assert.Error(t, err)

	_, err = ParseRuleIPOrCIDR("172.18.0.1@5")
	assert.ErrorIs(t, err, ErrRemoteClusterAddr)

	_, err = ParseRuleIPOrCIDR("172.18.0.1/16@5")
	assert.ErrorIs(t, err, ErrRemoteClusterAddr)
}
