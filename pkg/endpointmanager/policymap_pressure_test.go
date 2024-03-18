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
	p.gauge = &fakeGague{}
	assert.Equal(float64(0), p.gauge.(*fakeGague).Load())
	p.Update(endpoint.PolicyMapPressureEvent{
		EndpointID: 1,
		Value:      .5,
	})
	assertMetricEq := func(expected float64) {
		assert.Eventually(func() bool {
			return p.gauge.(*fakeGague).Load() == expected
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

type fakeGague struct {
	lastValue atomic.Value
}

func (f *fakeGague) Set(value float64) {
	f.lastValue.Store(value)
}

func (f *fakeGague) Load() float64 {
	v := f.lastValue.Load()
	if v == nil {
		return 0
	}
	return v.(float64)
}
