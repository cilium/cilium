/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package userspace

import (
	"net"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/proxy"
)

// LoadBalancer is an interface for distributing incoming requests to service endpoints.
type LoadBalancer interface {
	// NextEndpoint returns the endpoint to handle a request for the given
	// service-port and source address.
	NextEndpoint(service proxy.ServicePortName, srcAddr net.Addr, sessionAffinityReset bool) (string, error)
	NewService(service proxy.ServicePortName, sessionAffinityType api.ServiceAffinity, stickyMaxAgeSeconds int) error
	DeleteService(service proxy.ServicePortName)
	CleanupStaleStickySessions(service proxy.ServicePortName)
	ServiceHasEndpoints(service proxy.ServicePortName) bool
}
