// Copyright 2019 Authors of Cilium
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

package policy

// RedirectType indicates what kind id redirect is needed. RedirectTypes are bitmasks that can
// be ORed together to form a set of RedirectTypes needed for a set of L4Filters.
type RedirectType uint16

const (
	// RedirectTypeNone indicates no redirection
	RedirectTypeNone RedirectType = 0

	// RedirectTypeDNSEgress indicates a need for DNS egress redirect
	RedirectTypeDNSEgress RedirectType = 1 << iota
	// RedirectTypeKafkaIngress indicates a need for Kafka ingress redirect
	RedirectTypeKafkaIngress
	// RedirectTypeKafkaEgress indicates a need for Kafka egress redirect
	RedirectTypeKafkaEgress
	// RedirectTypeHTTPIngress indicates a need for HTTP ingress redirect
	RedirectTypeHTTPIngress
	// RedirectTypeHTTPEgress indicates a need for HTTP egress redirect
	RedirectTypeHTTPEgress
	// RedirectTypeProxylibIngress indicates a need for Proxylib ingress redirect
	RedirectTypeProxylibIngress
	// RedirectTypeProxylibEgress indicates a need for Proxylib egress redirect
	RedirectTypeProxylibEgress

	// RedirectTypeIngressMask is a mask of all ingress redirect types
	RedirectTypeIngressMask = RedirectTypeKafkaIngress | RedirectTypeHTTPIngress | RedirectTypeProxylibIngress

	// RedirectTypeEgressMask is a mask of all egress redirect types
	RedirectTypeEgressMask = RedirectTypeDNSEgress | RedirectTypeKafkaEgress | RedirectTypeHTTPEgress | RedirectTypeProxylibEgress

	// RedirectTypeAgentMask is a mask of all redirect types implemented in the Cilium Agent
	RedirectTypeAgentMask = RedirectTypeDNSEgress | RedirectTypeKafkaIngress | RedirectTypeKafkaEgress
)

// HasRedirects returns true if the L4Policy needs any L7 proxy redirects.
func (r RedirectType) HasRedirects() bool {
	return r != 0
}

// HasIngressRedirects returns true if the L4Policy needs any ingress L7 proxy redirects.
func (r RedirectType) HasIngressRedirects() bool {
	return r&RedirectTypeIngressMask != 0
}

// HasEgressRedirects returns true if the L4Policy needs any egress L7 proxy redirects.
func (r RedirectType) HasEgressRedirects() bool {
	return r&RedirectTypeEgressMask != 0
}

// HasAgentRedirects returns true if the L4Policy needs any L7 proxy redirects that run in the Cilium Agnet itself.
func (r RedirectType) HasAgentRedirects() bool {
	return r&RedirectTypeAgentMask != 0
}
