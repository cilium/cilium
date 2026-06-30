/*
Copyright The Kubernetes Authors.

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

package udp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

// ExpectedResponse describes optional assertions to make on the JSON envelope
// returned by the conformance UDP echo backend.
type ExpectedResponse struct {
	// Service, when non-empty, requires the responding backend to report this
	// value in the "service" field of the echo response JSON. Useful for tests
	// that wire multiple listeners to distinct backends and need to verify each
	// listener routes to the correct one.
	Service string
	// Namespace, when non-empty, requires the responding backend to report
	// this value in the "namespace" field of the echo response JSON.
	Namespace string
}

// echoResponse mirrors the JSON envelope produced by the conformance UDP echo
// backend. It is intentionally tolerant of unknown fields.
type echoResponse struct {
	Request   string `json:"request"`
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	Pod       string `json:"pod"`
}

// ExpectEchoResponse polls until a UDP echo round-trip against the given
// gateway address succeeds, or the timeout is exceeded.
func ExpectEchoResponse(t *testing.T, timeout time.Duration, gwAddr string) {
	t.Helper()
	ExpectEchoResponseFromBackend(t, timeout, gwAddr, ExpectedResponse{})
}

// ExpectEchoResponseFromBackend polls until a UDP echo round-trip against the
// given gateway address succeeds and (when set) the response identifies the
// expected backend Service and/or Namespace, or the timeout is exceeded.
func ExpectEchoResponseFromBackend(t *testing.T, timeout time.Duration, gwAddr string, expected ExpectedResponse) {
	t.Helper()

	const probe = "gateway-api-conformance-udp-echo"
	if expected.Service != "" || expected.Namespace != "" {
		tlog.Logf(t, "performing UDP echo probe on %s expecting backend service=%q namespace=%q",
			gwAddr, expected.Service, expected.Namespace)
	} else {
		tlog.Logf(t, "performing UDP echo probe on %s", gwAddr)
	}

	err := wait.PollUntilContextTimeout(context.TODO(), time.Second, timeout, true,
		func(ctx context.Context) (bool, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "udp", gwAddr)
			if err != nil {
				tlog.Logf(t, "failed to dial UDP %s: %v", gwAddr, err)
				return false, nil
			}
			defer conn.Close()

			if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return false, fmt.Errorf("setting UDP deadline: %w", err)
			}
			if _, err = conn.Write([]byte(probe)); err != nil {
				tlog.Logf(t, "failed to write UDP probe: %v", err)
				return false, nil
			}

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				tlog.Logf(t, "failed to read UDP echo response: %v", err)
				return false, nil
			}

			if expected.Service == "" && expected.Namespace == "" {
				tlog.Logf(t, "got UDP echo response (%d bytes) from %s", n, gwAddr)
				return true, nil
			}

			var resp echoResponse
			if err := json.Unmarshal(buf[:n], &resp); err != nil {
				tlog.Logf(t, "failed to decode UDP echo response from %s: %v", gwAddr, err)
				return false, nil
			}
			if expected.Service != "" && resp.Service != expected.Service {
				tlog.Logf(t, "UDP echo response service=%q did not match expected %q (gw=%s pod=%s)",
					resp.Service, expected.Service, gwAddr, resp.Pod)
				return false, nil
			}
			if expected.Namespace != "" && resp.Namespace != expected.Namespace {
				tlog.Logf(t, "UDP echo response namespace=%q did not match expected %q (gw=%s pod=%s)",
					resp.Namespace, expected.Namespace, gwAddr, resp.Pod)
				return false, nil
			}
			tlog.Logf(t, "got UDP echo response from %s service=%q namespace=%q pod=%q",
				gwAddr, resp.Service, resp.Namespace, resp.Pod)
			return true, nil
		})
	if err != nil {
		if expected.Service != "" || expected.Namespace != "" {
			t.Errorf("UDP echo probe never succeeded against %s with expected backend service=%q namespace=%q: %v",
				gwAddr, expected.Service, expected.Namespace, err)
			return
		}
		t.Errorf("UDP echo probe never succeeded against %s: %v", gwAddr, err)
	}
}
