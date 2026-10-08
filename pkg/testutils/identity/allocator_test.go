// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testidentity

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func TestOldNID(t *testing.T) {
	a := NewMockIdentityAllocator(nil)
	ctx := context.Background()

	// Request identity, it should work
	l := labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32"))
	id, _, _ := a.AllocateIdentity(ctx, l, false, 16777216)
	assert.NotNil(t, id)
	assert.EqualValues(t, 16777216, id.ID)

	// Re-request identity, it should not
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.2/32"))
	id, _, _ = a.AllocateIdentity(ctx, l, false, 16777216)
	assert.NotNil(t, id)
	assert.EqualValues(t, 16777217, id.ID)

	// Withhold the next identity, it should be skipped
	a.WithholdLocalIdentities([]identity.NumericIdentity{16777218})

	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.3/32"))
	id, _, _ = a.AllocateIdentity(ctx, l, false, 0)
	assert.NotNil(t, id)
	assert.EqualValues(t, 16777219, id.ID)

	// Request a withheld identity, it should succeed
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.4/32"))
	id, _, _ = a.AllocateIdentity(ctx, l, false, 16777218)
	assert.NotNil(t, id)
	assert.EqualValues(t, 16777218, id.ID)

	// Request a withheld and allocated identity, it should be ignored
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.5/32"))
	id, _, _ = a.AllocateIdentity(ctx, l, false, 16777218)
	assert.NotNil(t, id)
	assert.EqualValues(t, 16777220, id.ID)
}
