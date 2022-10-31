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

package http

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
)

// ExpectedResponse defines the response expected for a given request.
type ExpectedResponse struct {
	// Request defines the request to make.
	Request Request

	// ExpectedRequest defines the request that
	// is expected to arrive at the backend. If
	// not specified, the backend request will be
	// expected to match Request.
	ExpectedRequest *ExpectedRequest

	StatusCode int
	Backend    string
	Namespace  string
}

// Request can be used as both the request to make and a means to verify
// that echoserver received the expected request. Note that multiple header
// values can be provided, as a comma-separated value.
type Request struct {
	Host    string
	Method  string
	Path    string
	Headers map[string]string
}

// ExpectedRequest defines expected properties of a request.
type ExpectedRequest struct {
	Request

	// AbsentHeaders are names of headers that are expected
	// *not* to be present on the request.
	AbsentHeaders []string
}

// maxTimeToConsistency is the maximum time that WaitForConsistency will wait for
// requiredConsecutiveSuccesses requests to succeed in a row before failing the test.
const maxTimeToConsistency = 30 * time.Second

// requiredConsecutiveSuccesses is the number of requests that must succeed in a row
// for MakeRequestAndExpectEventuallyConsistentResponse to consider the response "consistent"
// before making additional assertions on the response body. If this number is not reached within
// maxTimeToConsistency, the test will fail.
const requiredConsecutiveSuccesses = 3

// MakeRequestAndExpectEventuallyConsistentResponse makes a request with the given parameters,
// understanding that the request may fail for some amount of time.
//
// Once the request succeeds consistently with the response having the expected status code, make
// additional assertions on the response body using the provided ExpectedResponse.
func MakeRequestAndExpectEventuallyConsistentResponse(t *testing.T, r roundtripper.RoundTripper, gwAddr string, expected ExpectedResponse) {
	t.Helper()

	if expected.Request.Method == "" {
		expected.Request.Method = "GET"
	}

	if expected.StatusCode == 0 {
		expected.StatusCode = 200
	}

	t.Logf("Making %s request to http://%s%s", expected.Request.Method, gwAddr, expected.Request.Path)

	path, query, _ := strings.Cut(expected.Request.Path, "?")

	req := roundtripper.Request{
		Method:   expected.Request.Method,
		Host:     expected.Request.Host,
		URL:      url.URL{Scheme: "http", Host: gwAddr, Path: path, RawQuery: query},
		Protocol: "HTTP",
	}

	if expected.Request.Headers != nil {
		req.Headers = map[string][]string{}
		for name, value := range expected.Request.Headers {
			req.Headers[name] = []string{value}
		}
	}

	WaitForConsistentResponse(t, r, req, expected, requiredConsecutiveSuccesses)
}

// awaitConvergence runs the given function until it returns 'true' `threshold` times in a row.
// Each failed attempt has a 1s delay; successful attempts have no delay.
func awaitConvergence(t *testing.T, threshold int, fn func() bool) {
	successes := 0
	attempts := 0
	to := time.After(maxTimeToConsistency)
	delay := time.Second
	for {
		select {
		case <-to:
			t.Fatalf("timeout while waiting after %d attempts", attempts)
		default:
		}

		completed := fn()
		attempts++
		if completed {
			successes++
			if successes >= threshold {
				return
			}
			// Skip delay if we have a success
			continue
		}

		successes = 0
		select {
		// Capture the overall timeout
		case <-to:
			t.Fatalf("timeout while waiting after %d attempts, %d/%d sucessess", attempts, successes, threshold)
			// And the per-try delay
		case <-time.After(delay):
		}
	}
}

// WaitForConsistentResponse repeats the provided request until it completes with a response having
// the expected response consistently. The provided threshold determines how many times in
// a row this must occur to be considered "consistent".
func WaitForConsistentResponse(t *testing.T, r roundtripper.RoundTripper, req roundtripper.Request, expected ExpectedResponse, threshold int) {
	awaitConvergence(t, threshold, func() bool {
		cReq, cRes, err := r.CaptureRoundTrip(req)
		if err != nil {
			t.Logf("Request failed, not ready yet: %v", err.Error())
			return false
		}

		if err := CompareRequest(cReq, cRes, expected); err != nil {
			t.Logf("Response expectation failed, not ready yet: %v", err)
			return false
		}

		return true
	})
	t.Logf("Request passed")
}

func CompareRequest(cReq *roundtripper.CapturedRequest, cRes *roundtripper.CapturedResponse, expected ExpectedResponse) error {
	if expected.StatusCode != cRes.StatusCode {
		return fmt.Errorf("expected status code to be %d, got %d", expected.StatusCode, cRes.StatusCode)
	}
	if cRes.StatusCode == 200 {
		// The request expected to arrive at the backend is
		// the same as the request made, unless otherwise
		// specified.
		if expected.ExpectedRequest == nil {
			expected.ExpectedRequest = &ExpectedRequest{Request: expected.Request}
		}

		if expected.ExpectedRequest.Method == "" {
			expected.ExpectedRequest.Method = "GET"
		}

		if expected.ExpectedRequest.Path != cReq.Path {
			return fmt.Errorf("expected path to be %s, got %s", expected.ExpectedRequest.Path, cReq.Path)
		}
		if expected.ExpectedRequest.Method != cReq.Method {
			return fmt.Errorf("expected method to be %s, got %s", expected.ExpectedRequest.Method, cReq.Method)
		}
		if expected.Namespace != cReq.Namespace {
			return fmt.Errorf("expected namespace to be %s, got %s", expected.Namespace, cReq.Namespace)
		}
		if expected.ExpectedRequest.Headers != nil {
			if cReq.Headers == nil {
				return fmt.Errorf("no headers captured, expected %v", len(expected.ExpectedRequest.Headers))
			}
			for name, val := range cReq.Headers {
				cReq.Headers[strings.ToLower(name)] = val
			}
			for name, expectedVal := range expected.ExpectedRequest.Headers {
				actualVal, ok := cReq.Headers[strings.ToLower(name)]
				if !ok {
					return fmt.Errorf("expected %s header to be set, actual headers: %v", name, cReq.Headers)
				} else if strings.Join(actualVal, ",") != expectedVal {
					return fmt.Errorf("expected %s header to be set to %s, got %s", name, expectedVal, strings.Join(actualVal, ","))
				}

			}
		}

		// Verify that headers expected *not* to be present on the
		// request are actually not present.
		if len(expected.ExpectedRequest.AbsentHeaders) > 0 {
			for name, val := range cReq.Headers {
				cReq.Headers[strings.ToLower(name)] = val
			}

			for _, name := range expected.ExpectedRequest.AbsentHeaders {
				val, ok := cReq.Headers[strings.ToLower(name)]
				if ok {
					return fmt.Errorf("expected %s header to not be set, got %s", name, val)
				}
			}
		}

		if !strings.HasPrefix(cReq.Pod, expected.Backend) {
			return fmt.Errorf("expected pod name to start with %s, got %s", expected.Backend, cReq.Pod)
		}
	}
	return nil
}
