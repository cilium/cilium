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
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// getProxyStatisticsLocked gets the ProxyStatistics for the flows with the
// given characteristics, or adds a new one and returns it.
// Must be called with e.proxyStatisticsMutex held.
func (e *Endpoint) getProxyStatisticsLocked(key string, l7Protocol string, port uint16, ingress bool) *models.ProxyStatistics {
	if e.proxyStatistics == nil {
		e.proxyStatistics = make(map[string]*models.ProxyStatistics)
	}

	proxyStats, ok := e.proxyStatistics[key]
	if !ok {
		var location string
		if ingress {
			location = models.ProxyStatisticsLocationIngress
		} else {
			location = models.ProxyStatisticsLocationEgress
		}
		proxyStats = &models.ProxyStatistics{
			Location: location,
			Port:     int64(port),
			Protocol: l7Protocol,
			Statistics: &models.RequestResponseStatistics{
				Requests:  &models.MessageForwardingStatistics{},
				Responses: &models.MessageForwardingStatistics{},
			},
		}

		e.proxyStatistics[key] = proxyStats
	}

	return proxyStats
}

// UpdateProxyStatistics updates the Endpoint's proxy  statistics to account
// for a new observed flow with the given characteristics.
func (e *Endpoint) UpdateProxyStatistics(l4Protocol string, port uint16, ingress, request bool, verdict accesslog.FlowVerdict) {
	e.proxyStatisticsMutex.Lock()
	defer e.proxyStatisticsMutex.Unlock()

	key := policy.ProxyID(e.ID, ingress, l4Protocol, port)
	proxyStats, ok := e.proxyStatistics[key]
	if !ok {
		e.getLogger().WithField(logfields.L4PolicyID, key).Warn("Proxy stats not found when updating")
		return
	}

	var stats *models.MessageForwardingStatistics
	if request {
		stats = proxyStats.Statistics.Requests
	} else {
		stats = proxyStats.Statistics.Responses
	}

	stats.Received++
	metrics.ProxyReceived.Inc()
	metrics.ProxyPolicyL7Total.WithLabelValues("received").Inc()

	switch verdict {
	case accesslog.VerdictForwarded:
		stats.Forwarded++
		metrics.ProxyForwarded.Inc()
		metrics.ProxyPolicyL7Total.WithLabelValues("forwarded").Inc()
	case accesslog.VerdictDenied:
		stats.Denied++
		metrics.ProxyDenied.Inc()
		metrics.ProxyPolicyL7Total.WithLabelValues("denied").Inc()
	case accesslog.VerdictError:
		stats.Error++
		metrics.ProxyParseErrors.Inc()
		metrics.ProxyPolicyL7Total.WithLabelValues("parse_errors").Inc()
	}
}

// sortProxyStats sorts the given slice of ProxyStatistics.
func sortProxyStats(proxyStats []*models.ProxyStatistics) {
	sort.Slice(proxyStats, func(i, j int) bool {
		s1, s2 := proxyStats[i], proxyStats[j]
		switch {
		case s1.Port < s2.Port:
			return true
		case s1.Port > s2.Port:
			return false
		}
		switch {
		case s1.Location < s2.Location:
			return true
		case s1.Location > s2.Location:
			return false
		}
		switch {
		case s1.Protocol < s2.Protocol:
			return true
		case s1.Protocol > s2.Protocol:
			return false
		}
		switch {
		case s1.AllocatedProxyPort < s2.AllocatedProxyPort:
			return true
		case s1.AllocatedProxyPort > s2.AllocatedProxyPort:
			return false
		}
		return false
	})
}
