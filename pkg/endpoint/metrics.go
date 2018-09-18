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
	"math"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
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

	for scope, value := range s.GetMap() {
		metrics.EndpointRegenerationTimeStats.WithLabelValues(scope).Observe(value.Seconds())
	}
}

// GetMap returns a map where the key is the stats name and the value is the duration of the stat.
func (s *regenerationStatistics) GetMap() map[string]time.Duration {
	return map[string]time.Duration{
		"waitingForLock":         s.waitingForLock.Total(),
		"waitingForCTClean":      s.waitingForCTClean.Total(),
		"policyCalculation":      s.policyCalculation.Total(),
		"proxyConfiguration":     s.proxyConfiguration.Total(),
		"proxyPolicyCalculation": s.proxyPolicyCalculation.Total(),
		"proxyWaitForAck":        s.proxyWaitForAck.Total(),
		"bpfCompilation":         s.bpfCompilation.Total(),
		"mapSync":                s.mapSync.Total(),
		"prepareBuild":           s.prepareBuild.Total(),
		logfields.BuildDuration:  s.totalTime.Total(),
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
