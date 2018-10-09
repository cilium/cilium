// Copyright 2018 Authors of Cilium
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

package endpoint

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
	"math"
	"sync"
	"time"
)

var (
	endpointPolicyStatus = new(endpointPolicyStatusMap)
)

type regenerationStatistics struct {
	success                bool
	endpointID             uint16
	policyStatus           models.EndpointPolicyEnabled
	totalTime              spanstat.SpanStat
	waitingForLock         spanstat.SpanStat
	waitingForCTClean      spanstat.SpanStat
	policyCalculation      spanstat.SpanStat
	proxyConfiguration     spanstat.SpanStat
	proxyPolicyCalculation spanstat.SpanStat
	proxyWaitForAck        spanstat.SpanStat
	bpfCompilation         spanstat.SpanStat
	mapSync                spanstat.SpanStat
	prepareBuild           spanstat.SpanStat
}

// SendMetrics sends the regeneration statistics for this endpoint to
// Prometheus.
func (s *regenerationStatistics) SendMetrics() {
	endpointPolicyStatus.Update(s.endpointID, s.policyStatus)
	metrics.EndpointCountRegenerating.Dec()

	if !s.success {
		// Endpoint regeneration failed, increase on failed metrics
		metrics.EndpointRegenerationCount.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		return
	}

	metrics.EndpointRegenerationCount.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	regenerateTimeSec := s.totalTime.Total().Seconds()
	metrics.EndpointRegenerationTime.Add(regenerateTimeSec)
	metrics.EndpointRegenerationTimeSquare.Add(math.Pow(regenerateTimeSec, 2))

	for scope, stat := range s.GetMap() {
		// Skip scopes that have not been hit (zero duration), so the count in
		// the histogram accurately reflects the number of times each scope is
		// hit, and the distribution is not incorrectly skewed towards zero.
		if stat.SuccessTotal() != time.Duration(0) {
			metrics.EndpointRegenerationTimeStats.WithLabelValues(scope, "success").Observe(stat.SuccessTotal().Seconds())
		}
		if stat.FailureTotal() != time.Duration(0) {
			metrics.EndpointRegenerationTimeStats.WithLabelValues(scope, "failure").Observe(stat.FailureTotal().Seconds())
		}
	}
}

// GetMap returns a map which key is the stat name and the value is the stat
func (s *regenerationStatistics) GetMap() map[string]*spanstat.SpanStat {
	return map[string]*spanstat.SpanStat{
		"waitingForLock":         &s.waitingForLock,
		"waitingForCTClean":      &s.waitingForCTClean,
		"policyCalculation":      &s.policyCalculation,
		"proxyConfiguration":     &s.proxyConfiguration,
		"proxyPolicyCalculation": &s.proxyPolicyCalculation,
		"proxyWaitForAck":        &s.proxyWaitForAck,
		"bpfCompilation":         &s.bpfCompilation,
		"mapSync":                &s.mapSync,
		"prepareBuild":           &s.prepareBuild,
		logfields.BuildDuration:  &s.totalTime,
	}
}

// endpointPolicyStatusMap is a map to store the endpoint id and the policy
// enforcement status. It is used only to send metrics to prometheus.
type endpointPolicyStatusMap struct {
	sync.Map
}

// Update adds or updates a new endpoint to the map and update the metrics
// related
func (epPolicyMaps *endpointPolicyStatusMap) Update(endpointID uint16, policyStatus models.EndpointPolicyEnabled) {
	epPolicyMaps.Store(endpointID, policyStatus)
	endpointPolicyStatus.UpdateMetrics()
}

// Remove deletes the given endpoint from the map and update the metrics
func (epPolicyMaps *endpointPolicyStatusMap) Remove(endpointID uint16) {
	epPolicyMaps.Delete(endpointID)
	epPolicyMaps.UpdateMetrics()
}

// UpdateMetrics update the policy enforcement metrics statistics for the endpoints.
func (epPolicyMaps *endpointPolicyStatusMap) UpdateMetrics() {
	policyStatus := map[models.EndpointPolicyEnabled]float64{
		models.EndpointPolicyEnabledNone:    0,
		models.EndpointPolicyEnabledEgress:  0,
		models.EndpointPolicyEnabledIngress: 0,
		models.EndpointPolicyEnabledBoth:    0,
	}

	epPolicyMaps.Range(func(key, value interface{}) bool {
		epPolicyStatus := value.(models.EndpointPolicyEnabled)
		policyStatus[epPolicyStatus]++
		return true
	})

	for k, v := range policyStatus {
		metrics.PolicyEndpointStatus.WithLabelValues(string(k)).Set(v)
	}
}
