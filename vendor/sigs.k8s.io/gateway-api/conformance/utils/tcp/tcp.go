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

package tcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tcpserver "sigs.k8s.io/gateway-api/conformance/echo-basic/tcpserver"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Dial(network, address string) (net.Conn, error)
}

type ExpectedResponse struct {
	BackendIsTLS bool
	Backend      string // Backend will be asserted from podname.
	Namespace    string
	TLSProtocol  string // Optional, if set will validate and value should match the definitions from tls.VersionName()
	Hostname     string // Optional, if set will verify if the SNI hostname captured by TLS matches this value
}

// MakeTCPRequestAndExpectEventuallyValidResponse makes a TCP request with the given parameters,
// understanding that the request may fail for some amount of time.
//
// Once the request succeeds consistently with the response having the answer for IS_TLS and desired information
// of the backend, it will pass, otherwise fails
func MakeTCPRequestAndExpectEventuallyValidResponse(t *testing.T, timeoutConfig config.TimeoutConfig, gwAddr string, serverCertificate []byte, serverName string, useTLS bool, expected ExpectedResponse) {
	t.Helper()

	var tlsConfig *tls.Config

	if useTLS {
		tlsConfig = &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
		if len(serverCertificate) > 0 {
			certPool := x509.NewCertPool()
			require.True(t, certPool.AppendCertsFromPEM(serverCertificate))
			tlsConfig.RootCAs = certPool
		}
	}
	dialer := makeClient(tlsConfig)
	WaitForValidTCPResponse(t, dialer, gwAddr, expected, timeoutConfig.MaxTimeToConsistency)
}

// WaitForConsistentTCPResponse - repeats the provided request until it completes with a response having
// the expected response consistently. The provided threshold determines how many times in
// a row this must occur to be considered "consistent".
// For every request, a new dial will happen so the following process will be verified:
// - WelcomeMessage matches
// - IS_TLS message matches
// - TEST message matches assertions
func WaitForValidTCPResponse(t *testing.T, dialer Dialer, gwAddr string, expected ExpectedResponse, maxTimeToConsistency time.Duration) {
	t.Helper()
	closeAndLog := func(t *testing.T, cl net.Conn, err error) bool {
		if err != nil {
			tlog.Logf(t, "an error occurred during assertion, will retry: %s", err)
		}
		if err := cl.Close(); err != nil {
			tlog.Logf(t, "error closing connection, will not fail but this can leak: %s", err)
		}
		return false
	}

	assert.Eventually(t, func() bool {
		client, err := dialer.DialContext(t.Context(), "tcp", gwAddr)
		if err != nil {
			tlog.Logf(t, "client could not connect: %s; retrying", err)
			return false
		}
		tlog.Logf(t, "tcp client connected")
		message, err := bufio.NewReader(client).ReadString('\n')
		if err != nil {
			return closeAndLog(t, client, err)
		}
		assert.Equal(t, tcpserver.WelcomeMessage, message, "TCPServer welcome message does not match")

		fmt.Fprintf(client, "PING\n")
		message, err = bufio.NewReader(client).ReadString('\n')
		if err != nil {
			return closeAndLog(t, client, err)
		}
		assert.Equal(t, "PONG\n", message)

		fmt.Fprintf(client, "IS_TLS\n")
		message, err = bufio.NewReader(client).ReadString('\n')
		if err != nil {
			return closeAndLog(t, client, err)
		}
		assert.Equal(t, fmt.Sprintf("%t", expected.BackendIsTLS), strings.TrimSuffix(message, "\n"))

		fmt.Fprintf(client, "TEST\n")
		message, err = bufio.NewReader(client).ReadString('\n')
		if err != nil {
			return closeAndLog(t, client, err)
		}

		payload := &tcpserver.TCPAssertions{}
		if err := json.Unmarshal([]byte(message), payload); err != nil {
			return closeAndLog(t, client, err)
		}

		// At this moment we can simply assume the message will be right, or fail
		assertTestMessage(t, payload, expected)
		return true
	}, maxTimeToConsistency, time.Second)

	tlog.Logf(t, "Request passed")
}

func makeClient(tlsConfig *tls.Config) Dialer {
	if tlsConfig == nil {
		return &net.Dialer{}
	}

	return &tls.Dialer{
		Config: tlsConfig,
	}
}

func assertTestMessage(t *testing.T, payload *tcpserver.TCPAssertions, expected ExpectedResponse) {
	t.Helper()
	require.NotNil(t, payload)
	assert.Equal(t, expected.Namespace, payload.Namespace, "namespace does not match")
	assert.True(t, strings.HasPrefix(payload.Pod, fmt.Sprintf("%s-", expected.Backend)), "backend name does not match with pod prefix. pod=%s and backend=%s", payload.Pod, expected.Backend) // Pod must contain "backend-"
	if expected.Hostname != "" {
		assert.Equal(t, expected.Hostname, payload.TLSAssertion.ServerName)
	}
	if expected.TLSProtocol != "" {
		assert.Equal(t, expected.TLSProtocol, payload.TLSAssertion.NegotiatedProtocol)
	}
}
