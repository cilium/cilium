// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package k8s

import (
	"gopkg.in/check.v1"
)

func (s *K8sSuite) TestK8sPkgConfiguration(c *check.C) {
	c.Assert(GetAPIServerURL(), check.IsNil)
	c.Assert(config.APIServerURLs, check.HasLen, 0)

	Configure([]string{"http://192.168.0.1"}, "/home/cilium/.kube/config", 100, 10)

	c.Assert(GetAPIServerURLString(), check.Equals, "http://192.168.0.1")
	c.Assert(config.APIServerURLs, check.HasLen, 1)
	c.Assert(GetKubeconfigPath(), check.Equals, "/home/cilium/.kube/config")
	c.Assert(GetBurst(), check.Equals, 10)
	c.Assert(GetQPS(), check.Equals, float32(100))

	config = configuration{}
	Configure([]string{"192.168.0.1:6443"}, "", 100, 10)

	c.Assert(GetAPIServerURLString(), check.Equals, "http://192.168.0.1:6443")
	c.Assert(config.APIServerURLs, check.HasLen, 1)

	config = configuration{}
	Configure([]string{"http://192.168.0.1", "https://192.168.0.2", "https://192.168.0.3"}, "", 100, 10)

	c.Assert(GetAPIServerURLString(), check.Equals, "http://192.168.0.1")
	RotateAPIServerURL()
	c.Assert(GetAPIServerURLString() != "http://192.168.0.1", check.Equals, true)
	c.Assert(GetAPIServerURL().Scheme, check.Equals, "http")
	c.Assert(config.APIServerURLs, check.HasLen, 3)

	config = configuration{}
	Configure([]string{"192.168.0.1:6443", "https://192.168.0.2:6443", " AAAA", ""}, "", 100, 10)

	c.Assert(GetAPIServerURLString(), check.Equals, "http://192.168.0.1:6443")
	RotateAPIServerURL()
	c.Assert(GetAPIServerURLString(), check.Equals, "http://192.168.0.2:6443")
	c.Assert(config.APIServerURLs, check.HasLen, 2)
}
