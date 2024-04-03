// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
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
	assert.Equal(float64(0), p.gauge.(*fakeGague).lastValue)
	p.Update(endpoint.PolicyMapPressureEvent{
		EndpointID: 1,
		Value:      .5,
	})
	assertMetricEq := func(expected float64) {
		assert.Eventually(func() bool {
			return p.gauge.(*fakeGague).lastValue == expected
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
	lastValue float64
}

func (f *fakeGague) Set(value float64) {
	f.lastValue = value
}
