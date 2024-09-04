/*
Copyright 2022 The Kubernetes Authors.

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

package tests

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, UDPRouteTest)
}

var UDPRouteTest = suite.ConformanceTest{
	ShortName:   "UDPRoute",
	Description: "Make sure UDPRoute is working",
	Manifests:   []string{"tests/udproute-simple.yaml"},
	Features: []features.FeatureName{
		features.SupportUDPRoute,
		features.SupportGateway,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		t.Run("Simple UDP request matching UDPRoute should reach coredns backend", func(t *testing.T) {
			namespace := "gateway-conformance-infra"
			domain := "foo.bar.com."
			routeNN := types.NamespacedName{Name: "udp-coredns", Namespace: namespace}
			gwNN := types.NamespacedName{Name: "udp-gateway", Namespace: namespace}
			gwAddr := kubernetes.GatewayAndUDPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

			msg := new(dns.Msg)
			msg.SetQuestion(domain, dns.TypeA)

			if err := wait.PollUntilContextTimeout(context.TODO(), time.Second, time.Minute, true,
				func(_ context.Context) (done bool, err error) {
					t.Logf("performing DNS query %s on %s", domain, gwAddr)
					_, err = dns.Exchange(msg, gwAddr)
					if err != nil {
						t.Logf("failed to perform a UDP query: %v", err)
						return false, nil
					}
					return true, nil
				}); err != nil {
				t.Errorf("failed to perform DNS query: %v", err)
			}
		})
	},
}
