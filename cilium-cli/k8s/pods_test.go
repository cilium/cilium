// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSupersededPodRejection(t *testing.T) {
	for _, reason := range []string{"TaintToleration", "NodeAffinity", "NodeLost", "Evicted", "Shutdown", "Preempting", "UnexpectedAdmissionError"} {
		assert.True(t, IsSupersededPodRejection(reason), reason)
	}
	for _, reason := range []string{"", "OOMKilled", "Error", "ContainerCannotRun"} {
		assert.False(t, IsSupersededPodRejection(reason), reason)
	}
}
