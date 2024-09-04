/*
Copyright 2023 The Kubernetes Authors.

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
	"bytes"
	"fmt"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests,
		HTTPRouteBackendProtocolWebSocket,
	)
}

var HTTPRouteBackendProtocolWebSocket = suite.ConformanceTest{
	ShortName:   "HTTPRouteBackendProtocolWebSocket",
	Description: "A HTTPRoute with a BackendRef that has an appProtocol kubernetes.io/ws should be functional",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteBackendProtocolWebSocket,
	},
	Manifests: []string{
		"tests/httproute-backend-protocol-websocket.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "backend-protocol-ws", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		threshold := suite.TimeoutConfig.RequiredConsecutiveSuccesses
		maxTimeToConsistency := suite.TimeoutConfig.MaxTimeToConsistency

		t.Run("websocket connection should reach backend", func(t *testing.T) {
			http.AwaitConvergence(t, threshold, maxTimeToConsistency, func(_ time.Duration) bool {
				origin := fmt.Sprintf("ws://gateway/%s", t.Name())
				remote := fmt.Sprintf("ws://%s/ws", gwAddr)

				ws, err := websocket.Dial(remote, "", origin)
				if err != nil {
					t.Log("failed to dial", err)
					return false
				}
				defer ws.Close()

				// Send text frame
				var (
					textMessage = "Websocket Support!"
					textReply   string
				)
				if err := websocket.Message.Send(ws, textMessage); err != nil {
					t.Log("failed to send text frame", err)
					return false
				}
				if err := websocket.Message.Receive(ws, &textReply); err != nil {
					t.Log("failed to receive text frame", err)
					return false
				}
				if textMessage != textReply {
					t.Logf("unexpected reply - want: %s got: %s", textMessage, textReply)
					return false
				}

				// Send byte frame
				var (
					binaryMessage = []byte{1, 2, 3, 4, 5, 6, 7}
					binaryReply   []byte
				)
				if err := websocket.Message.Send(ws, binaryMessage); err != nil {
					t.Log("failed to send binary frame", err)
					return false
				}
				if err := websocket.Message.Receive(ws, &binaryReply); err != nil {
					t.Log("failed to receive binary frame", err)
				}
				if !bytes.Equal(binaryMessage, binaryReply) {
					t.Logf("unexpected reply - want: %#v got: %#v", binaryMessage, binaryReply)
					return false
				}
				return true
			})
		})
	},
}
