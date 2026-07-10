// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"time"
)

type Metrics interface {
	StartDuration(time.Duration)
	StopDuration(time.Duration)
	PopulateDuration(time.Duration)
}

type NopMetrics struct{}

// StartDuration implements Metrics.
func (NopMetrics) StartDuration(duration time.Duration) {
}

// StopDuration implements Metrics.
func (NopMetrics) StopDuration(duration time.Duration) {
}

// PopulateDuration implements Metrics.
func (NopMetrics) PopulateDuration(duration time.Duration) {
}

var _ Metrics = NopMetrics{}
