// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"testing"

	"github.com/stretchr/testify/require"

	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
)

func TestGetDefaultMonitorQueueSize(t *testing.T) {
	require.Equal(t, 4*ciliumDefaults.MonitorQueueSizePerCPU, getDefaultMonitorQueueSize(4))
	require.Equal(t, ciliumDefaults.MonitorQueueSizePerCPUMaximum, getDefaultMonitorQueueSize(1000))
}
