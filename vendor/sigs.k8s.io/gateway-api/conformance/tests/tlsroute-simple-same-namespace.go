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
	"fmt"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
)

func init() {
	ConformanceTests = append(ConformanceTests, TLSRouteSimpleSameNamespace)
}

var TLSRouteSimpleSameNamespace = suite.ConformanceTest{
	ShortName:   "TLSRouteSimpleSameNamespace",
	Description: "A single TLSRoute in the gateway-conformance-infra namespace attaches to a Gateway in the same namespace",
	Manifests:   []string{"tests/tlsroute-simple-same-namespace.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := v1beta1.Namespace("gateway-conformance-infra")
		routeNN := types.NamespacedName{Name: "gateway-conformance-infra-test", Namespace: string(ns)}
		gwNN := types.NamespacedName{Name: "gateway-tlsroute", Namespace: string(ns)}
		certNN := types.NamespacedName{Name: "tls-passthrough-checks-certificate", Namespace: string(ns)}

		gwAddr, hostnames := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		if len(hostnames) != 1 {
			t.Fatalf("unexpected error in test configuration, found %d hostnames", len(hostnames))
		}
		serverStr := string(hostnames[0])

		cPem, keyPem, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}
		t.Run("Simple TLS request matching TLSRoute should reach infra-backend", func(t *testing.T) {
			tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, cPem, keyPem, serverStr,
				http.ExpectedResponse{
					Request:   http.Request{Host: serverStr, Path: "/"},
					Backend:   "tls-backend",
					Namespace: "gateway-conformance-infra",
				})
		})
	},
}

// GetTLSSecret fetches the named Secret and converts both cert and key to []byte
func GetTLSSecret(client client.Client, secretName types.NamespacedName) ([]byte, []byte, error) {
	var cert, key []byte

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret := &v1.Secret{}
	err := client.Get(ctx, secretName, secret)
	if err != nil {
		return cert, key, fmt.Errorf("error fetching TLS Secret: %w", err)
	}
	cert = secret.Data["tls.crt"]
	key = secret.Data["tls.key"]

	return cert, key, nil
}
