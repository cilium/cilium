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

// +build !privileged_tests

package policy

import (
	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestRedirectType(c *C) {
	// Test individual types
	c.Assert(RedirectTypeNone.HasRedirects(), Equals, false)
	c.Assert(RedirectTypeDNSEgress.HasRedirects(), Equals, true)
	c.Assert(RedirectTypeDNSEgress.HasIngressRedirects(), Equals, false)
	c.Assert(RedirectTypeDNSEgress.HasEgressRedirects(), Equals, true)
	c.Assert(RedirectTypeDNSEgress.HasAgentRedirects(), Equals, true)
	c.Assert(RedirectTypeKafkaIngress.HasRedirects(), Equals, true)
	c.Assert(RedirectTypeKafkaIngress.HasIngressRedirects(), Equals, true)
	c.Assert(RedirectTypeKafkaIngress.HasEgressRedirects(), Equals, false)
	c.Assert(RedirectTypeKafkaIngress.HasAgentRedirects(), Equals, true)
	c.Assert(RedirectTypeKafkaEgress.HasRedirects(), Equals, true)
	c.Assert(RedirectTypeKafkaEgress.HasIngressRedirects(), Equals, false)
	c.Assert(RedirectTypeKafkaEgress.HasEgressRedirects(), Equals, true)
	c.Assert(RedirectTypeKafkaEgress.HasAgentRedirects(), Equals, true)
	c.Assert(RedirectTypeHTTPIngress.HasRedirects(), Equals, true)
	c.Assert(RedirectTypeHTTPIngress.HasIngressRedirects(), Equals, true)
	c.Assert(RedirectTypeHTTPIngress.HasEgressRedirects(), Equals, false)
	c.Assert(RedirectTypeHTTPIngress.HasAgentRedirects(), Equals, false)
	c.Assert(RedirectTypeHTTPEgress.HasRedirects(), Equals, true)
	c.Assert(RedirectTypeHTTPEgress.HasIngressRedirects(), Equals, false)
	c.Assert(RedirectTypeHTTPEgress.HasEgressRedirects(), Equals, true)
	c.Assert(RedirectTypeHTTPEgress.HasAgentRedirects(), Equals, false)
	c.Assert(RedirectTypeProxylibIngress.HasRedirects(), Equals, true)
	c.Assert(RedirectTypeProxylibIngress.HasIngressRedirects(), Equals, true)
	c.Assert(RedirectTypeProxylibIngress.HasEgressRedirects(), Equals, false)
	c.Assert(RedirectTypeProxylibIngress.HasAgentRedirects(), Equals, false)
	c.Assert(RedirectTypeProxylibEgress.HasRedirects(), Equals, true)
	c.Assert(RedirectTypeProxylibEgress.HasIngressRedirects(), Equals, false)
	c.Assert(RedirectTypeProxylibEgress.HasEgressRedirects(), Equals, true)
	c.Assert(RedirectTypeProxylibEgress.HasAgentRedirects(), Equals, false)

	// Test multiple types together
	redirects := RedirectTypeHTTPIngress | RedirectTypeHTTPEgress
	c.Assert(redirects.HasRedirects(), Equals, true)
	c.Assert(redirects.HasIngressRedirects(), Equals, true)
	c.Assert(redirects.HasEgressRedirects(), Equals, true)
	c.Assert(redirects.HasAgentRedirects(), Equals, false)

	redirects = RedirectTypeDNSEgress | RedirectTypeHTTPEgress
	c.Assert(redirects.HasRedirects(), Equals, true)
	c.Assert(redirects.HasIngressRedirects(), Equals, false)
	c.Assert(redirects.HasEgressRedirects(), Equals, true)
	c.Assert(redirects.HasAgentRedirects(), Equals, true)
}
