// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"github.com/cilium/hive/cell"
)

type metricsServer struct{}

// Start implements cell.HookInterface.
func (s *metricsServer) Start(_ cell.HookContext) error {
	return nil
}

// Stop implements cell.HookInterface.
func (s *metricsServer) Stop(_ cell.HookContext) error {
	return nil
}
