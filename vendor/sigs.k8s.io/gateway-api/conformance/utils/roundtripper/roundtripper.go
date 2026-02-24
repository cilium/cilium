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

package roundtripper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"testing"

	"golang.org/x/net/http2"

	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

const (
	H2CPriorKnowledgeProtocol = "H2C_PRIOR_KNOWLEDGE"
)

// RoundTripper is an interface used to make requests within conformance tests.
// This can be overridden with custom implementations whenever necessary.
type RoundTripper interface {
	CaptureRoundTrip(Request) (*CapturedRequest, *CapturedResponse, error)
}

// Request is the primary input for making a request.
type Request struct {
	T                *testing.T
	URL              url.URL
	Host             string
	Protocol         string
	Method           string
	Headers          map[string][]string
	UnfollowRedirect bool
	CertPem          []byte
	KeyPem           []byte
	Server           string
}

// String returns a printable version of Request for logging. Note that the
// CertPem and KeyPem are truncated.
func (r Request) String() string {
	return fmt.Sprintf("{URL: %+v, Host: %v, Protocol: %v, Method: %v, Headers: %v, UnfollowRedirect: %v, Server: %v, CertPem: <truncated>, KeyPem: <truncated>}",
		r.URL,
		r.Host,
		r.Protocol,
		r.Method,
		r.Headers,
		r.UnfollowRedirect,
		r.Server,
	)
}

// CapturedRequest contains request metadata captured from an echoserver
// response.
type CapturedRequest struct {
	Path     string              `json:"path"`
	Host     string              `json:"host"`
	Method   string              `json:"method"`
	Protocol string              `json:"proto"`
	Headers  map[string][]string `json:"headers"`

	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
}

// RedirectRequest contains a follow up request metadata captured from a redirect
// response.
type RedirectRequest struct {
	Scheme string
	Host   string
	Port   string
	Path   string
}

// CapturedResponse contains response metadata.
type CapturedResponse struct {
	StatusCode       int
	ContentLength    int64
	Protocol         string
	Headers          map[string][]string
	RedirectRequest  *RedirectRequest
	PeerCertificates []*x509.Certificate
}

// DefaultRoundTripper is the default implementation of a RoundTripper. It will
// be used if a custom implementation is not specified.
type DefaultRoundTripper struct {
	Debug             bool
	TimeoutConfig     config.TimeoutConfig
	CustomDialContext func(context.Context, string, string) (net.Conn, error)
}

func (d *DefaultRoundTripper) httpTransport(request Request) (http.RoundTripper, error) {
	transport := &http.Transport{
		DialContext: d.CustomDialContext,
		// We disable keep-alives so that we don't leak established TCP connections.
		// Leaking TCP connections is bad because we could eventually hit the
		// threshold of maximum number of open TCP connections to a specific
		// destination. Keep-alives are not presently utilized so disabling this has
		// no adverse affect.
		//
		// Ref. https://github.com/kubernetes-sigs/gateway-api/issues/2357
		DisableKeepAlives: true,
	}
	if request.Server != "" && len(request.CertPem) != 0 && len(request.KeyPem) != 0 {
		tlsConfig, err := tlsClientConfig(request.Server, request.CertPem, request.KeyPem)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}

	return transport, nil
}

func (d *DefaultRoundTripper) h2cPriorKnowledgeTransport(request Request) (http.RoundTripper, error) {
	if request.Server != "" && len(request.CertPem) != 0 && len(request.KeyPem) != 0 {
		return nil, errors.New("request has configured cert and key but h2 prior knowledge is not encrypted")
	}

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	return transport, nil
}

// CaptureRoundTrip makes a request with the provided parameters and returns the
// captured request and response from echoserver. An error will be returned if
// there is an error running the function but not if an HTTP error status code
// is received.
func (d *DefaultRoundTripper) CaptureRoundTrip(request Request) (*CapturedRequest, *CapturedResponse, error) {
	var transport http.RoundTripper
	var err error

	switch request.Protocol {
	case H2CPriorKnowledgeProtocol:
		transport, err = d.h2cPriorKnowledgeTransport(request)
	default:
		transport, err = d.httpTransport(request)
	}

	if err != nil {
		return nil, nil, err
	}

	return d.defaultRoundTrip(request, transport)
}

func (d *DefaultRoundTripper) defaultRoundTrip(request Request, transport http.RoundTripper) (*CapturedRequest, *CapturedResponse, error) {
	client := &http.Client{}

	if request.UnfollowRedirect {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	client.Transport = transport

	method := "GET"
	if request.Method != "" {
		method = request.Method
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.TimeoutConfig.RequestTimeout)
	defer cancel()
	ctx = withT(ctx, request.T)
	req, err := http.NewRequestWithContext(ctx, method, request.URL.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	if request.Host != "" {
		req.Host = request.Host
	}

	if request.Headers != nil {
		for name, value := range request.Headers {
			req.Header.Set(name, value[0])
		}
	}

	if d.Debug {
		var dump []byte
		dump, err = httputil.DumpRequestOut(req, true)
		if err != nil {
			return nil, nil, err
		}

		tlog.Logf(request.T, "Sending Request:\n%s\n\n", formatDump(dump, "< "))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if d.Debug {
		var dump []byte
		dump, err = httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, nil, err
		}

		tlog.Logf(request.T, "Received Response:\n%s\n\n", formatDump(dump, "< "))
	}

	cReq := &CapturedRequest{}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	// we cannot assume the response is JSON
	if resp.Header.Get("Content-type") == "application/json" {
		err = json.Unmarshal(body, cReq)
		if err != nil {
			return nil, nil, fmt.Errorf("unexpected error reading response: %w", err)
		}
	} else {
		cReq.Method = method // assume it made the right request if the service being called isn't echoing
	}

	cRes := &CapturedResponse{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		Protocol:      resp.Proto,
		Headers:       resp.Header,
	}

	if resp.TLS != nil {
		cRes.PeerCertificates = resp.TLS.PeerCertificates
	}

	if IsRedirect(resp.StatusCode) {
		redirectURL, err := resp.Location()
		if err != nil {
			return nil, nil, err
		}
		cRes.RedirectRequest = &RedirectRequest{
			Scheme: redirectURL.Scheme,
			Host:   redirectURL.Hostname(),
			Port:   redirectURL.Port(),
			Path:   redirectURL.Path,
		}
	}

	return cReq, cRes, nil
}

func tlsClientConfig(server string, certPem []byte, keyPem []byte) (*tls.Config, error) {
	// Create a certificate from the provided cert and key
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating cert: %w", err)
	}

	// Add the provided cert as a trusted CA
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPem) {
		return nil, fmt.Errorf("unexpected error adding trusted CA: %w", err)
	}

	if server == "" {
		return nil, fmt.Errorf("unexpected error, server name required for TLS")
	}

	// Create the tls Config for this provided host, cert, and trusted CA
	// Disable G402: TLS MinVersion too low. (gosec)
	// #nosec G402
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   server,
		RootCAs:      certPool,
	}, nil
}

// IsRedirect returns true if a given status code is a redirect code.
func IsRedirect(statusCode int) bool {
	switch statusCode {
	case http.StatusMultipleChoices,
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusNotModified,
		http.StatusUseProxy,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	}
	return false
}

// IsTimeoutError returns true if a given status code is a timeout error code.
func IsTimeoutError(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// testingTContextKey is the key for adding testing.T to the context.Context
type testingTContextKey struct{}

// withT returns a context with the testing.T added as a value.
func withT(ctx context.Context, t *testing.T) context.Context {
	return context.WithValue(ctx, testingTContextKey{}, t)
}

// TFromContext returns the testing.T added to the context if available.
func TFromContext(ctx context.Context) (*testing.T, bool) {
	v := ctx.Value(testingTContextKey{})
	if v != nil {
		if t, ok := v.(*testing.T); ok {
			return t, true
		}
	}
	return nil, false
}

var startLineRegex = regexp.MustCompile(`(?m)^`)

func formatDump(data []byte, prefix string) string {
	data = startLineRegex.ReplaceAllLiteral(data, []byte(prefix))
	return string(data)
}
