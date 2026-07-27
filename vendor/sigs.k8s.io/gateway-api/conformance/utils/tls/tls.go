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

package tls

import (
	cryptotls "crypto/tls"
	"errors"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

// MakeTLSRequestAndExpectEventuallyConsistentResponse makes a request with the given parameters,
// understanding that the request may fail for some amount of time.
//
// Once the request succeeds consistently with the response having the expected status code, make
// additional assertions on the response body using the provided ExpectedResponse.
func MakeTLSRequestAndExpectEventuallyConsistentResponse(t *testing.T, r roundtripper.RoundTripper, timeoutConfig config.TimeoutConfig, gwAddr string, serverCertificate, clientCertificate, clientCertificateKey []byte, serverName string, expected http.ExpectedResponse) {
	t.Helper()

	req := http.MakeRequest(t, &expected, gwAddr, roundtripper.HTTPSProtocol, "https")
	req.ServerName = serverName
	req.ServerCertificate = serverCertificate

	var clientCertificatePresented bool
	if clientCertificate != nil && clientCertificateKey != nil {
		certificate, err := cryptotls.X509KeyPair(clientCertificate, clientCertificateKey)
		if err != nil {
			t.Fatalf("unexpected error creating client cert: %v", err)
		}

		// GetClientCertificateHook is a hook called when server asks for client certificate during TLS handshake,
		// to verify that a client certificate has been requested.
		req.GetClientCertificateHook = func(_ *cryptotls.CertificateRequestInfo) (*cryptotls.Certificate, error) {
			t.Log("GetClientCertificateHook was called")
			clientCertificatePresented = true
			return &certificate, nil
		}
	}

	WaitForConsistentTLSResponse(t, r, req, expected, timeoutConfig.RequiredConsecutiveSuccesses, timeoutConfig.MaxTimeToConsistency)

	if clientCertificate != nil && clientCertificateKey != nil {
		assert.True(t, clientCertificatePresented, "client certificate was not presented during the handshake")
	}
}

// WaitForConsistentTLSResponse - repeats the provided request until it completes with a response having
// the expected response consistently. The provided threshold determines how many times in
// a row this must occur to be considered "consistent".
func WaitForConsistentTLSResponse(t *testing.T, r roundtripper.RoundTripper, req roundtripper.Request, expected http.ExpectedResponse, threshold int, maxTimeToConsistency time.Duration) {
	http.AwaitConvergence(t, threshold, maxTimeToConsistency, func(elapsed time.Duration) bool {
		cReq, cRes, err := r.CaptureRoundTrip(req)
		if err != nil {
			tlog.Logf(t, "Request failed, not ready yet: %v (after %v)", err.Error(), elapsed)
			return false
		}

		if err := http.CompareRoundTrip(t, &req, cReq, cRes, expected); err != nil {
			tlog.Logf(t, "Response expectation failed for request: %+v  not ready yet: %v (after %v)", req, err, elapsed)
			tlog.Logf(t, "Full response: %+v", cReq)
			return false
		}

		return true
	})
	tlog.Logf(t, "Request passed")
}

// MakeTLSRequestAndExpectFailureResponse makes one shot request. This function fails
// when HTTP Status OK (200) is returned.
func MakeTLSRequestAndExpectFailureResponse(t *testing.T, r roundtripper.RoundTripper, gwAddr string, serverCertificate, clientCertificate, clientCertificateKey []byte, serverName string, expected http.ExpectedResponse) {
	t.Helper()

	req := http.MakeRequest(t, &expected, gwAddr, roundtripper.HTTPSProtocol, "https")
	req.ServerName = serverName
	req.ServerCertificate = serverCertificate

	var clientCertificatePresented bool
	if clientCertificate != nil && clientCertificateKey != nil {
		certificate, err := cryptotls.X509KeyPair(clientCertificate, clientCertificateKey)
		if err != nil {
			t.Fatalf("unexpected error creating client cert: %v", err)
		}

		// GetClientCertificateHook is a hook called when server asks for client certificate during TLS handshake,
		// to verify that a client certificate has been requested.
		req.GetClientCertificateHook = func(_ *cryptotls.CertificateRequestInfo) (*cryptotls.Certificate, error) {
			t.Log("GetClientCertificateHook was called")
			clientCertificatePresented = true
			return &certificate, nil
		}
	}

	_, _, err := r.CaptureRoundTrip(req)
	if err == nil {
		t.Fatalf("Request should fail")
	}

	if clientCertificate != nil && clientCertificateKey != nil {
		assert.True(t, clientCertificatePresented, "client certificate was not presented during the handshake")
	}
}

// MakeTLSConnectionAndExpectEventuallyConnectionRejection initiates a TCP connection, then initiates TLS Handshake, and expects the TCP connection to be eventually rejected.
// This is useful for testing scenarios where a Gateway accepts a TCP connection but then closes it due to not matching SNI or invalid routing configuration.
func MakeTLSConnectionAndExpectEventuallyConnectionRejection(t *testing.T, timeoutConfig config.TimeoutConfig, gwAddr string, serverName string) {
	t.Helper()

	dialer := &cryptotls.Dialer{
		Config: &cryptotls.Config{
			ServerName: serverName,
			MinVersion: cryptotls.VersionTLS12,
		},
	}

	assert.Eventually(t, func() bool {
		_, err := dialer.DialContext(t.Context(), "tcp", gwAddr)
		if err != nil {
			if isConnectionRejected(err) {
				tlog.Logf(t, "connection was rejected during dial: %s", err)
				return true
			}
			tlog.Logf(t, "client could not connect: %s; retrying", err)
			return false
		}
		tlog.Logf(t, "client could connect")
		return false
	}, timeoutConfig.MaxTimeToConsistency, time.Second)
}

// isConnectionRejected checks if an error indicates either a TCP RST (ECONNRESET)
// or a TCP FIN-style close (EOF).
func isConnectionRejected(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if strings.Contains(err.Error(), "connection reset by peer") {
		return true
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		return sysErr == syscall.ECONNRESET
	}
	return false
}
