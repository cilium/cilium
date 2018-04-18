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
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

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

// UpdateProxyStatistics updates the Endpoint's proxy  statistics to account
// for a new observed flow with the given characteristics.
func (e *Endpoint) UpdateProxyStatistics(l7Protocol string, port uint16, ingress, request bool, verdict accesslog.FlowVerdict) {
	e.proxyStatisticsMutex.Lock()
	defer e.proxyStatisticsMutex.Unlock()

	proxyStats := e.getProxyStatisticsLocked(l7Protocol, port, ingress)

	var stats *models.MessageForwardingStatistics
	if request {
		stats = proxyStats.Statistics.Requests
	} else {
		stats = proxyStats.Statistics.Responses
	}

	stats.Received++

	switch verdict {
	case accesslog.VerdictForwarded:
		stats.Forwarded++
	case accesslog.VerdictDenied:
		stats.Denied++
	case accesslog.VerdictError:
		stats.Error++
	}
}

// getProxyStatisticsLocked gets the ProxyStatistics for the flows with the
// given characteristics, or adds a new one and returns it.
// Must be called with e.proxyStatisticsMutex held.
func (e *Endpoint) getProxyStatisticsLocked(l7Protocol string, port uint16, ingress bool) *models.ProxyStatistics {
	var location string
	if ingress {
		location = models.ProxyStatisticsLocationIngress
	} else {
		location = models.ProxyStatisticsLocationEgress
	}
	key := models.ProxyStatistics{
		Location: location,
		Port:     int64(port),
		Protocol: l7Protocol,
	}

	if e.proxyStatistics == nil {
		e.proxyStatistics = make(map[models.ProxyStatistics]*models.ProxyStatistics)
	}

	proxyStats, ok := e.proxyStatistics[key]
	if !ok {
		keyCopy := key
		proxyStats = &keyCopy
		proxyStats.Statistics = &models.RequestResponseStatistics{
			Requests:  &models.MessageForwardingStatistics{},
			Responses: &models.MessageForwardingStatistics{},
		}
		e.proxyStatistics[key] = proxyStats
	}

	return proxyStats
}
