// Copyright 2019-2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	assert.False(t, filterByVerdicts([]flowpb.Verdict{flowpb.Verdict_REDIRECTED})(ev))
}
