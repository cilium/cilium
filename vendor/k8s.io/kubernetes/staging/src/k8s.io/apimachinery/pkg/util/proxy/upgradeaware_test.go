/*
Copyright 2017 The Kubernetes Authors.

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

package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/net/websocket"

	"k8s.io/apimachinery/pkg/util/httpstream"
	utilnet "k8s.io/apimachinery/pkg/util/net"
)

const fakeStatusCode = 567

type fakeResponder struct {
	t      *testing.T
	called bool
	err    error
	// called chan error
	w http.ResponseWriter
}

func (r *fakeResponder) Error(w http.ResponseWriter, req *http.Request, err error) {
	if r.called {
		r.t.Errorf("Error responder called again!\nprevious error: %v\nnew error: %v", r.err, err)
	}

	w.WriteHeader(fakeStatusCode)
	_, writeErr := w.Write([]byte(err.Error()))
	assert.NoError(r.t, writeErr)

	r.called = true
	r.err = err
}

type fakeConn struct {
	err error // The error to return when io is performed over the connection.
}

func (f *fakeConn) Read([]byte) (int, error)        { return 0, f.err }
func (f *fakeConn) Write([]byte) (int, error)       { return 0, f.err }
func (f *fakeConn) Close() error                    { return nil }
func (fakeConn) LocalAddr() net.Addr                { return nil }
func (fakeConn) RemoteAddr() net.Addr               { return nil }
func (fakeConn) SetDeadline(t time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(t time.Time) error { return nil }

type SimpleBackendHandler struct {
	requestURL     url.URL
	requestHeader  http.Header
	requestBody    []byte
	requestMethod  string
	responseBody   string
	responseHeader map[string]string
	t              *testing.T
}

func (s *SimpleBackendHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.requestURL = *req.URL
	s.requestHeader = req.Header
	s.requestMethod = req.Method
	var err error
	s.requestBody, err = ioutil.ReadAll(req.Body)
	if err != nil {
		s.t.Errorf("Unexpected error: %v", err)
		return
	}

	if s.responseHeader != nil {
		for k, v := range s.responseHeader {
			w.Header().Add(k, v)
		}
	}
	w.Write([]byte(s.responseBody))
}

func validateParameters(t *testing.T, name string, actual url.Values, expected map[string]string) {
	for k, v := range expected {
		actualValue, ok := actual[k]
		if !ok {
			t.Errorf("%s: Expected parameter %s not received", name, k)
			continue
		}
		if actualValue[0] != v {
			t.Errorf("%s: Parameter %s values don't match. Actual: %#v, Expected: %s",
				name, k, actualValue, v)
		}
	}
}

func validateHeaders(t *testing.T, name string, actual http.Header, expected map[string]string, notExpected []string) {
	for k, v := range expected {
		actualValue, ok := actual[k]
		if !ok {
			t.Errorf("%s: Expected header %s not received", name, k)
			continue
		}
		if actualValue[0] != v {
			t.Errorf("%s: Header %s values don't match. Actual: %s, Expected: %s",
				name, k, actualValue, v)
		}
	}
	if notExpected == nil {
		return
	}
	for _, h := range notExpected {
		if _, present := actual[h]; present {
			t.Errorf("%s: unexpected header: %s", name, h)
		}
	}
}

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		name                  string
		method                string
		requestPath           string
		expectedPath          string
		requestBody           string
		requestParams         map[string]string
		requestHeader         map[string]string
		responseHeader        map[string]string
		expectedRespHeader    map[string]string
		notExpectedRespHeader []string
		upgradeRequired       bool
		expectError           func(err error) bool
	}{
		{
			name:         "root path, simple get",
			method:       "GET",
			requestPath:  "/",
			expectedPath: "/",
		},
		{
			name:            "no upgrade header sent",
			method:          "GET",
			requestPath:     "/",
			upgradeRequired: true,
			expectError: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "Upgrade request required")
			},
		},
		{
			name:         "simple path, get",
			method:       "GET",
			requestPath:  "/path/to/test",
			expectedPath: "/path/to/test",
		},
		{
			name:          "request params",
			method:        "POST",
			requestPath:   "/some/path/",
			expectedPath:  "/some/path/",
			requestParams: map[string]string{"param1": "value/1", "param2": "value%2"},
			requestBody:   "test request body",
		},
		{
			name:          "request headers",
			method:        "PUT",
			requestPath:   "/some/path",
			expectedPath:  "/some/path",
			requestHeader: map[string]string{"Header1": "value1", "Header2": "value2"},
		},
		{
			name:         "empty path - slash should be added",
			method:       "GET",
			requestPath:  "",
			expectedPath: "/",
		},
		{
			name:         "remove CORS headers",
			method:       "GET",
			requestPath:  "/some/path",
			expectedPath: "/some/path",
			responseHeader: map[string]string{
				"Header1":                      "value1",
				"Access-Control-Allow-Origin":  "some.server",
				"Access-Control-Allow-Methods": "GET"},
			expectedRespHeader: map[string]string{
				"Header1": "value1",
			},
			notExpectedRespHeader: []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Methods",
			},
		},
	}

	for i, test := range tests {
		func() {
			backendResponse := "<html><head></head><body><a href=\"/test/path\">Hello</a></body></html>"
			backendResponseHeader := test.responseHeader
			// Test a simple header if not specified in the test
			if backendResponseHeader == nil && test.expectedRespHeader == nil {
				backendResponseHeader = map[string]string{"Content-Type": "text/html"}
				test.expectedRespHeader = map[string]string{"Content-Type": "text/html"}
			}
			backendHandler := &SimpleBackendHandler{
				responseBody:   backendResponse,
				responseHeader: backendResponseHeader,
			}
			backendServer := httptest.NewServer(backendHandler)
			defer backendServer.Close()

			responder := &fakeResponder{t: t}
			backendURL, _ := url.Parse(backendServer.URL)
			backendURL.Path = test.requestPath
			proxyHandler := NewUpgradeAwareHandler(backendURL, nil, false, test.upgradeRequired, responder)
			proxyServer := httptest.NewServer(proxyHandler)
			defer proxyServer.Close()
			proxyURL, _ := url.Parse(proxyServer.URL)
			proxyURL.Path = test.requestPath
			paramValues := url.Values{}
			for k, v := range test.requestParams {
				paramValues[k] = []string{v}
			}
			proxyURL.RawQuery = paramValues.Encode()
			var requestBody io.Reader
			if test.requestBody != "" {
				requestBody = bytes.NewBufferString(test.requestBody)
			}
			req, err := http.NewRequest(test.method, proxyURL.String(), requestBody)
			if test.requestHeader != nil {
				header := http.Header{}
				for k, v := range test.requestHeader {
					header.Add(k, v)
				}
				req.Header = header
			}
			if err != nil {
				t.Errorf("Error creating client request: %v", err)
			}
			client := &http.Client{}
			res, err := client.Do(req)
			if err != nil {
				t.Errorf("Error from proxy request: %v", err)
			}

			if test.expectError != nil {
				if !responder.called {
					t.Errorf("%d: responder was not invoked", i)
					return
				}
				if !test.expectError(responder.err) {
					t.Errorf("%d: unexpected error: %v", i, responder.err)
				}
				return
			}

			// Validate backend request
			// Method
			if backendHandler.requestMethod != test.method {
				t.Errorf("Unexpected request method: %s. Expected: %s",
					backendHandler.requestMethod, test.method)
			}

			// Body
			if string(backendHandler.requestBody) != test.requestBody {
				t.Errorf("Unexpected request body: %s. Expected: %s",
					string(backendHandler.requestBody), test.requestBody)
			}

			// Path
			if backendHandler.requestURL.Path != test.expectedPath {
				t.Errorf("Unexpected request path: %s", backendHandler.requestURL.Path)
			}
			// Parameters
			validateParameters(t, test.name, backendHandler.requestURL.Query(), test.requestParams)

			// Headers
			validateHeaders(t, test.name+" backend request", backendHandler.requestHeader,
				test.requestHeader, nil)

			// Validate proxy response

			// Response Headers
			validateHeaders(t, test.name+" backend headers", res.Header, test.expectedRespHeader, test.notExpectedRespHeader)

			// Validate Body
			responseBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Errorf("Unexpected error reading response body: %v", err)
			}
			if rb := string(responseBody); rb != backendResponse {
				t.Errorf("Did not get expected response body: %s. Expected: %s", rb, backendResponse)
			}

			// Error
			if responder.called {
				t.Errorf("Unexpected proxy handler error: %v", responder.err)
			}
		}()
	}
}

type RoundTripperFunc func(req *http.Request) (*http.Response, error)

func (fn RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestProxyUpgrade(t *testing.T) {

	localhostPool := x509.NewCertPool()
	if !localhostPool.AppendCertsFromPEM(localhostCert) {
		t.Errorf("error setting up localhostCert pool")
	}

	testcases := map[string]struct {
		ServerFunc       func(http.Handler) *httptest.Server
		ProxyTransport   http.RoundTripper
		UpgradeTransport UpgradeRequestRoundTripper
		ExpectedAuth     string
	}{
		"http": {
			ServerFunc:     httptest.NewServer,
			ProxyTransport: nil,
		},
		"https (invalid hostname + InsecureSkipVerify)": {
			ServerFunc: func(h http.Handler) *httptest.Server {
				cert, err := tls.X509KeyPair(exampleCert, exampleKey)
				if err != nil {
					t.Errorf("https (invalid hostname): proxy_test: %v", err)
				}
				ts := httptest.NewUnstartedServer(h)
				ts.TLS = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}
				ts.StartTLS()
				return ts
			},
			ProxyTransport: utilnet.SetTransportDefaults(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}),
		},
		"https (valid hostname + RootCAs)": {
			ServerFunc: func(h http.Handler) *httptest.Server {
				cert, err := tls.X509KeyPair(localhostCert, localhostKey)
				if err != nil {
					t.Errorf("https (valid hostname): proxy_test: %v", err)
				}
				ts := httptest.NewUnstartedServer(h)
				ts.TLS = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}
				ts.StartTLS()
				return ts
			},
			ProxyTransport: utilnet.SetTransportDefaults(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: localhostPool}}),
		},
		"https (valid hostname + RootCAs + custom dialer)": {
			ServerFunc: func(h http.Handler) *httptest.Server {
				cert, err := tls.X509KeyPair(localhostCert, localhostKey)
				if err != nil {
					t.Errorf("https (valid hostname): proxy_test: %v", err)
				}
				ts := httptest.NewUnstartedServer(h)
				ts.TLS = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}
				ts.StartTLS()
				return ts
			},
			ProxyTransport: utilnet.SetTransportDefaults(&http.Transport{Dial: net.Dial, TLSClientConfig: &tls.Config{RootCAs: localhostPool}}),
		},
		"https (valid hostname + RootCAs + custom dialer + bearer token)": {
			ServerFunc: func(h http.Handler) *httptest.Server {
				cert, err := tls.X509KeyPair(localhostCert, localhostKey)
				if err != nil {
					t.Errorf("https (valid hostname): proxy_test: %v", err)
				}
				ts := httptest.NewUnstartedServer(h)
				ts.TLS = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}
				ts.StartTLS()
				return ts
			},
			ProxyTransport: utilnet.SetTransportDefaults(&http.Transport{Dial: net.Dial, TLSClientConfig: &tls.Config{RootCAs: localhostPool}}),
			UpgradeTransport: NewUpgradeRequestRoundTripper(
				utilnet.SetOldTransportDefaults(&http.Transport{Dial: net.Dial, TLSClientConfig: &tls.Config{RootCAs: localhostPool}}),
				RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					req = utilnet.CloneRequest(req)
					req.Header.Set("Authorization", "Bearer 1234")
					return MirrorRequest.RoundTrip(req)
				}),
			),
			ExpectedAuth: "Bearer 1234",
		},
	}

	for k, tc := range testcases {
		for _, redirect := range []bool{false, true} {
			tcName := k
			backendPath := "/hello"
			if redirect {
				tcName += " with redirect"
				backendPath = "/redirect"
			}
			func() { // Cleanup after each test case.
				backend := http.NewServeMux()
				backend.Handle("/hello", websocket.Handler(func(ws *websocket.Conn) {
					if ws.Request().Header.Get("Authorization") != tc.ExpectedAuth {
						t.Errorf("%s: unexpected headers on request: %v", k, ws.Request().Header)
						defer ws.Close()
						ws.Write([]byte("you failed"))
						return
					}
					defer ws.Close()
					body := make([]byte, 5)
					ws.Read(body)
					ws.Write([]byte("hello " + string(body)))
				}))
				backend.Handle("/redirect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "/hello", http.StatusFound)
				}))
				backendServer := tc.ServerFunc(backend)
				defer backendServer.Close()

				serverURL, _ := url.Parse(backendServer.URL)
				serverURL.Path = backendPath
				proxyHandler := NewUpgradeAwareHandler(serverURL, tc.ProxyTransport, false, false, &noErrorsAllowed{t: t})
				proxyHandler.UpgradeTransport = tc.UpgradeTransport
				proxyHandler.InterceptRedirects = redirect
				proxy := httptest.NewServer(proxyHandler)
				defer proxy.Close()

				ws, err := websocket.Dial("ws://"+proxy.Listener.Addr().String()+"/some/path", "", "http://127.0.0.1/")
				if err != nil {
					t.Fatalf("%s: websocket dial err: %s", tcName, err)
				}
				defer ws.Close()

				if _, err := ws.Write([]byte("world")); err != nil {
					t.Fatalf("%s: write err: %s", tcName, err)
				}

				response := make([]byte, 20)
				n, err := ws.Read(response)
				if err != nil {
					t.Fatalf("%s: read err: %s", tcName, err)
				}
				if e, a := "hello world", string(response[0:n]); e != a {
					t.Fatalf("%s: expected '%#v', got '%#v'", tcName, e, a)
				}
			}()
		}
	}
}

type noErrorsAllowed struct {
	t *testing.T
}

func (r *noErrorsAllowed) Error(w http.ResponseWriter, req *http.Request, err error) {
	r.t.Error(err)
}

func TestProxyUpgradeErrorResponse(t *testing.T) {
	var (
		responder   *fakeResponder
		expectedErr = errors.New("EXPECTED")
	)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		transport := http.DefaultTransport.(*http.Transport)
		transport.Dial = func(network, addr string) (net.Conn, error) {
			return &fakeConn{err: expectedErr}, nil
		}
		responder = &fakeResponder{t: t, w: w}
		proxyHandler := NewUpgradeAwareHandler(
			&url.URL{
				Host: "fake-backend",
			},
			transport,
			false,
			true,
			responder,
		)
		proxyHandler.ServeHTTP(w, r)
	}))
	defer proxy.Close()

	// Send request to proxy server.
	req, err := http.NewRequest("POST", "http://"+proxy.Listener.Addr().String()+"/some/path", nil)
	require.NoError(t, err)
	req.Header.Set(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Expect error response.
	assert.True(t, responder.called)
	assert.Equal(t, fakeStatusCode, resp.StatusCode)
	msg, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(msg), expectedErr.Error())
}

func TestDefaultProxyTransport(t *testing.T) {
	tests := []struct {
		name,
		url,
		location,
		expectedScheme,
		expectedHost,
		expectedPathPrepend string
	}{
		{
			name:                "simple path",
			url:                 "http://test.server:8080/a/test/location",
			location:            "http://localhost/location",
			expectedScheme:      "http",
			expectedHost:        "test.server:8080",
			expectedPathPrepend: "/a/test",
		},
		{
			name:                "empty path",
			url:                 "http://test.server:8080/a/test/",
			location:            "http://localhost",
			expectedScheme:      "http",
			expectedHost:        "test.server:8080",
			expectedPathPrepend: "/a/test",
		},
		{
			name:                "location ending in slash",
			url:                 "http://test.server:8080/a/test/",
			location:            "http://localhost/",
			expectedScheme:      "http",
			expectedHost:        "test.server:8080",
			expectedPathPrepend: "/a/test",
		},
	}

	for _, test := range tests {
		locURL, _ := url.Parse(test.location)
		URL, _ := url.Parse(test.url)
		h := NewUpgradeAwareHandler(locURL, nil, false, false, nil)
		result := h.defaultProxyTransport(URL, nil)
		transport := result.(*corsRemovingTransport).RoundTripper.(*Transport)
		if transport.Scheme != test.expectedScheme {
			t.Errorf("%s: unexpected scheme. Actual: %s, Expected: %s", test.name, transport.Scheme, test.expectedScheme)
		}
		if transport.Host != test.expectedHost {
			t.Errorf("%s: unexpected host. Actual: %s, Expected: %s", test.name, transport.Host, test.expectedHost)
		}
		if transport.PathPrepend != test.expectedPathPrepend {
			t.Errorf("%s: unexpected path prepend. Actual: %s, Expected: %s", test.name, transport.PathPrepend, test.expectedPathPrepend)
		}
	}
}

func TestProxyRequestContentLengthAndTransferEncoding(t *testing.T) {
	chunk := func(data []byte) []byte {
		out := &bytes.Buffer{}
		chunker := httputil.NewChunkedWriter(out)
		for _, b := range data {
			if _, err := chunker.Write([]byte{b}); err != nil {
				panic(err)
			}
		}
		chunker.Close()
		out.Write([]byte("\r\n"))
		return out.Bytes()
	}

	zip := func(data []byte) []byte {
		out := &bytes.Buffer{}
		zipper := gzip.NewWriter(out)
		if _, err := zipper.Write(data); err != nil {
			panic(err)
		}
		zipper.Close()
		return out.Bytes()
	}

	sampleData := []byte("abcde")

	table := map[string]struct {
		reqHeaders http.Header
		reqBody    []byte

		expectedHeaders http.Header
		expectedBody    []byte
	}{
		"content-length": {
			reqHeaders: http.Header{
				"Content-Length": []string{"5"},
			},
			reqBody: sampleData,

			expectedHeaders: http.Header{
				"Content-Length":    []string{"5"},
				"Content-Encoding":  nil, // none set
				"Transfer-Encoding": nil, // none set
			},
			expectedBody: sampleData,
		},

		"content-length + identity transfer-encoding": {
			reqHeaders: http.Header{
				"Content-Length":    []string{"5"},
				"Transfer-Encoding": []string{"identity"},
			},
			reqBody: sampleData,

			expectedHeaders: http.Header{
				"Content-Length":    []string{"5"},
				"Content-Encoding":  nil, // none set
				"Transfer-Encoding": nil, // gets removed
			},
			expectedBody: sampleData,
		},

		"content-length + gzip content-encoding": {
			reqHeaders: http.Header{
				"Content-Length":   []string{strconv.Itoa(len(zip(sampleData)))},
				"Content-Encoding": []string{"gzip"},
			},
			reqBody: zip(sampleData),

			expectedHeaders: http.Header{
				"Content-Length":    []string{strconv.Itoa(len(zip(sampleData)))},
				"Content-Encoding":  []string{"gzip"},
				"Transfer-Encoding": nil, // none set
			},
			expectedBody: zip(sampleData),
		},

		"chunked transfer-encoding": {
			reqHeaders: http.Header{
				"Transfer-Encoding": []string{"chunked"},
			},
			reqBody: chunk(sampleData),

			expectedHeaders: http.Header{
				"Content-Length":    nil, // none set
				"Content-Encoding":  nil, // none set
				"Transfer-Encoding": nil, // Transfer-Encoding gets removed
			},
			expectedBody: sampleData, // sample data is unchunked
		},

		"chunked transfer-encoding + gzip content-encoding": {
			reqHeaders: http.Header{
				"Content-Encoding":  []string{"gzip"},
				"Transfer-Encoding": []string{"chunked"},
			},
			reqBody: chunk(zip(sampleData)),

			expectedHeaders: http.Header{
				"Content-Length":    nil, // none set
				"Content-Encoding":  []string{"gzip"},
				"Transfer-Encoding": nil, // gets removed
			},
			expectedBody: zip(sampleData), // sample data is unchunked, but content-encoding is preserved
		},

		// "Transfer-Encoding: gzip" is not supported by go
		// See http/transfer.go#fixTransferEncoding (https://golang.org/src/net/http/transfer.go#L427)
		// Once it is supported, this test case should succeed
		//
		// "gzip+chunked transfer-encoding": {
		// 	reqHeaders: http.Header{
		// 		"Transfer-Encoding": []string{"chunked,gzip"},
		// 	},
		// 	reqBody: chunk(zip(sampleData)),
		//
		// 	expectedHeaders: http.Header{
		// 		"Content-Length":    nil, // no content-length headers
		// 		"Transfer-Encoding": nil, // Transfer-Encoding gets removed
		// 	},
		// 	expectedBody: sampleData,
		// },
	}

	successfulResponse := "backend passed tests"
	for k, item := range table {
		// Start the downstream server
		downstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Verify headers
			for header, v := range item.expectedHeaders {
				if !reflect.DeepEqual(v, req.Header[header]) {
					t.Errorf("%s: Expected headers for %s to be %v, got %v", k, header, v, req.Header[header])
				}
			}

			// Read body
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Errorf("%s: unexpected error %v", k, err)
			}
			req.Body.Close()

			// Verify length
			if req.ContentLength > 0 && req.ContentLength != int64(len(body)) {
				t.Errorf("%s: ContentLength was %d, len(data) was %d", k, req.ContentLength, len(body))
			}

			// Verify content
			if !bytes.Equal(item.expectedBody, body) {
				t.Errorf("%s: Expected %q, got %q", k, string(item.expectedBody), string(body))
			}

			// Write successful response
			w.Write([]byte(successfulResponse))
		}))
		defer downstreamServer.Close()

		responder := &fakeResponder{t: t}
		backendURL, _ := url.Parse(downstreamServer.URL)
		proxyHandler := NewUpgradeAwareHandler(backendURL, nil, false, false, responder)
		proxyServer := httptest.NewServer(proxyHandler)
		defer proxyServer.Close()

		// Dial the proxy server
		conn, err := net.Dial(proxyServer.Listener.Addr().Network(), proxyServer.Listener.Addr().String())
		if err != nil {
			t.Errorf("unexpected error %v", err)
			continue
		}
		defer conn.Close()

		// Add standard http 1.1 headers
		if item.reqHeaders == nil {
			item.reqHeaders = http.Header{}
		}
		item.reqHeaders.Add("Connection", "close")
		item.reqHeaders.Add("Host", proxyServer.Listener.Addr().String())

		// Write the request headers
		if _, err := fmt.Fprint(conn, "POST / HTTP/1.1\r\n"); err != nil {
			t.Fatalf("%s unexpected error %v", k, err)
		}
		for header, values := range item.reqHeaders {
			for _, value := range values {
				if _, err := fmt.Fprintf(conn, "%s: %s\r\n", header, value); err != nil {
					t.Fatalf("%s: unexpected error %v", k, err)
				}
			}
		}
		// Header separator
		if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
			t.Fatalf("%s: unexpected error %v", k, err)
		}
		// Body
		if _, err := conn.Write(item.reqBody); err != nil {
			t.Fatalf("%s: unexpected error %v", k, err)
		}

		// Read response
		response, err := ioutil.ReadAll(conn)
		if err != nil {
			t.Errorf("%s: unexpected error %v", k, err)
			continue
		}
		if !strings.HasSuffix(string(response), successfulResponse) {
			t.Errorf("%s: Did not get successful response: %s", k, string(response))
			continue
		}
	}
}

// exampleCert was generated from crypto/tls/generate_cert.go with the following command:
//    go run generate_cert.go  --rsa-bits 512 --host example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var exampleCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBdzCCASGgAwIBAgIRAOVTAdPnfbS5V85mfS90TfIwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgC
QQCoVSqeu8TBvF+70T7Jm4340YQNhds6IxjRoifenYodAO1dnKGrcbF266DJGunh
nIjQH7B12tduhl0fLK4Ezf7/AgMBAAGjUDBOMA4GA1UdDwEB/wQEAwICpDATBgNV
HSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBYGA1UdEQQPMA2CC2V4
YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA0EAk1kVa5uZ/AzwYDVcS9bpM/czwjjV
xq3VeSCfmNa2uNjbFvodmCRwZOHUvipAMGCUCV6j5vMrJ8eMj8tCQ36W9A==
-----END CERTIFICATE-----`)

var exampleKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKhVKp67xMG8X7vRPsmbjfjRhA2F2zojGNGiJ96dih0A7V2coatx
sXbroMka6eGciNAfsHXa126GXR8srgTN/v8CAwEAAQJASdzdD7vKsUwMIejGCUb1
fAnLTPfAY3lFCa+CmR89nE22dAoRDv+5RbnBsZ58BazPNJHrsVPRlfXB3OQmSQr0
SQIhANoJhs+xOJE/i8nJv0uAbzKyiD1YkvRkta0GpUOULyAVAiEAxaQus3E/SuqD
P7y5NeJnE7X6XkyC35zrsJRkz7orE8MCIHdDjsI8pjyNDeGqwUCDWE/a6DrmIDwe
emHSqMN2YvChAiEAnxLCM9NWaenOsaIoP+J1rDuvw+4499nJKVqGuVrSCRkCIEqK
4KSchPMc3x8M/uhw9oWTtKFmjA/PPh0FsWCdKrEy
-----END RSA PRIVATE KEY-----`)
