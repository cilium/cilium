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
