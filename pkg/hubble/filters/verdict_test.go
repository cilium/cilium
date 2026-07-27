// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestVerdictFilter(t *testing.T) {
	ev := &v1.Event{
		Event: &flowpb.Flow{
			Verdict: flowpb.Verdict_FORWARDED,
		},
	}
	assert.True(t, filterByVerdicts([]flowpb.Verdict{flowpb.Verdict_FORWARDED})(ev))
	assert.False(t, filterByVerdicts([]flowpb.Verdict{flowpb.Verdict_DROPPED})(ev))
	assert.False(t, filterByVerdicts([]flowpb.Verdict{flowpb.Verdict_REDIRECTED})(ev))
}
