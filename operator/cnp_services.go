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

package main

import (
	"net"

	"github.com/cilium/cilium/pkg/policy/api"
)

func init() {
	api.RegisterServiceProvider("k8s-service", getIPs)
}

func getIPs(svc *api.Service) []net.IP {
	result := []net.IP{}

	if svc.K8sServiceSelector != nil || svc.K8sService != nil {
		for _, endpoints := range k8sSvcCache.LookupEndpoints(svc) {
			for ipString := range endpoints.Backends {
				ip := net.ParseIP(ipString)
				if ip == nil {
					log.Warningf("Encountered invalid IP address: %s", ipString)
					continue
				}
				result = append(result, ip)
			}
		}

		log.Debugf("Resolved endpoints for service selector %#v to %#v", svc, result)
	}

	return result
}
