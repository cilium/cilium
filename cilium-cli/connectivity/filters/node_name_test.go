// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestNodeName(t *testing.T) {
	filter := NodeName("worker")
	flowContext := NewFlowContext()
	assert.True(t, filter.Match(&flowpb.Flow{NodeName: "worker"}, &flowContext))
	assert.True(t, filter.Match(&flowpb.Flow{NodeName: "cluster/worker"}, &flowContext))
	assert.False(t, filter.Match(&flowpb.Flow{NodeName: "cluster/other-worker"}, &flowContext))
}
