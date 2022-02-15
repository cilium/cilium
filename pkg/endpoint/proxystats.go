// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"sort"

	"github.com/cilium/cilium/api/v1/models"
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
