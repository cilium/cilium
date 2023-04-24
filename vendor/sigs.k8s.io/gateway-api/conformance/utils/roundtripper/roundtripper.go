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
	"fmt"
	"io"
	iou "io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"

	"sigs.k8s.io/gateway-api/conformance/utils/config"
)

// RoundTripper is an interface used to make requests within conformance tests.
// This can be overridden with custom implementations whenever necessary.
type RoundTripper interface {
	CaptureRoundTrip(Request) (*CapturedRequest, *CapturedResponse, error)
}

// Request is the primary input for making a request.
type Request struct {
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
	StatusCode      int
	ContentLength   int64
	Protocol        string
	Headers         map[string][]string
	RedirectRequest *RedirectRequest
}

// DefaultRoundTripper is the default implementation of a RoundTripper. It will
// be used if a custom implementation is not specified.
type DefaultRoundTripper struct {
	Debug         bool
	TimeoutConfig config.TimeoutConfig
}

// CaptureRoundTrip makes a request with the provided parameters and returns the
// captured request and response from echoserver. An error will be returned if
// there is an error running the function but not if an HTTP error status code
// is received.
func (d *DefaultRoundTripper) CaptureRoundTrip(request Request) (*CapturedRequest, *CapturedResponse, error) {
	cReq := &CapturedRequest{}
	client := &http.Client{}

	if request.UnfollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Setup TLS transport if there are CertPem, KeyPem, and Server in the request
	if request.Server != "" && len(request.CertPem) != 0 && len(request.KeyPem) != 0 {
		// Create a certificate from the provided cert and key
		cert, err := tls.X509KeyPair(request.CertPem, request.KeyPem)
		if err != nil {
			return nil, nil, fmt.Errorf("unexpected error creating cert: %w", err)
		}

		// Add the provided cert as a trusted CA
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(request.CertPem) {
			return nil, nil, fmt.Errorf("unexpected error adding trusted CA: %w", err)
		}

		if request.Server == "" {
			return nil, nil, fmt.Errorf("unexpected error, server name required for TLS")
		}

		// Create the Transport for this provided host, cert, and trusted CA
		client.Transport = &http.Transport{
			// Disable G402: TLS MinVersion too low. (gosec)
			// #nosec G402
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				ServerName:   request.Server,
				RootCAs:      certPool,
			},
		}
	}

	method := "GET"
	if request.Method != "" {
		method = request.Method
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.TimeoutConfig.RequestTimeout)
	defer cancel()
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

		fmt.Printf("Sending Request:\n%s\n\n", formatDump(dump, "< "))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if d.Debug {
		var dump []byte
		dump, err = httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, nil, err
		}

		fmt.Printf("Received Response:\n%s\n\n", formatDump(dump, "< "))
	}

	body, _ := iou.ReadAll(resp.Body)

	// we cannot assume the response is JSON
	if resp.Header.Get("Content-type") == "application/json" {
		err = json.Unmarshal(body, cReq)
		if err != nil {
			return nil, nil, fmt.Errorf("unexpected error reading response: %w", err)
		}
	}

	cRes := &CapturedResponse{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		Protocol:      resp.Proto,
		Headers:       resp.Header,
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

var startLineRegex = regexp.MustCompile(`(?m)^`)

func formatDump(data []byte, prefix string) string {
	data = startLineRegex.ReplaceAllLiteral(data, []byte(prefix))
	return string(data)
}
