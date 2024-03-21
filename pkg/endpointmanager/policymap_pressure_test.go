// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/endpoint"
)

func TestPolicyMapPressure(t *testing.T) {
	assert := assert.New(t)
	policyMapPressureMinInterval = 0
	p := newPolicyMapPressure()
	p.gauge = &fakeGauge{}
	assert.Equal(float64(0), p.gauge.(*fakeGauge).Load())
	p.Update(endpoint.PolicyMapPressureEvent{
		EndpointID: 1,
		Value:      .5,
	})
	assertMetricEq := func(expected float64) {
		assert.Eventually(func() bool {
			return p.gauge.(*fakeGauge).Load() == expected
		}, time.Second, 1*time.Millisecond)
	}
	assertMetricEq(.5)
	p.Update(endpoint.PolicyMapPressureEvent{
		EndpointID: 2,
		Value:      1,
	})
	assertMetricEq(1)
	p.Remove(2)
	assertMetricEq(.5)
}

type fakeGauge struct {
	lastValue atomic.Value
}

func (f *fakeGauge) Set(value float64) {
	f.lastValue.Store(value)
}

func (f *fakeGauge) Load() float64 {
	v := f.lastValue.Load()
	if v == nil {
		return 0
	}
	return v.(float64)
}
