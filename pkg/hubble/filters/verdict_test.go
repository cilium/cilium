// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Hubble

// +build !privileged_tests

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"

	"github.com/stretchr/testify/assert"
)

func TestVerdictFilter(t *testing.T) {
	ev := &v1.Event{
		Event: &flowpb.Flow{
			Verdict: flowpb.Verdict_FORWARDED,
		},
	}
	assert.True(t, filterByVerdicts([]flowpb.Verdict{flowpb.Verdict_FORWARDED})(ev))
	assert.False(t, filterByVerdicts([]flowpb.Verdict{flowpb.Verdict_DROPPED})(ev))
}
