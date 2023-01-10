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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"time"
)

// RoundTripper is an interface used to make requests within conformance tests.
// This can be overridden with custom implementations whenever necessary.
type RoundTripper interface {
	CaptureRoundTrip(Request) (*CapturedRequest, *CapturedResponse, error)
}

// Request is the primary input for making a request.
type Request struct {
	URL      url.URL
	Host     string
	Protocol string
	Method   string
	Headers  map[string][]string
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

// CapturedResponse contains response metadata.
type CapturedResponse struct {
	StatusCode    int
	ContentLength int64
	Protocol      string
	Headers       map[string][]string
}

// DefaultRoundTripper is the default implementation of a RoundTripper. It will
// be used if a custom implementation is not specified.
type DefaultRoundTripper struct {
	Debug bool
}

// CaptureRoundTrip makes a request with the provided parameters and returns the
// captured request and response from echoserver. An error will be returned if
// there is an error running the function but not if an HTTP error status code
// is received.
func (d *DefaultRoundTripper) CaptureRoundTrip(request Request) (*CapturedRequest, *CapturedResponse, error) {
	cReq := &CapturedRequest{}
	client := http.DefaultClient

	method := "GET"
	if request.Method != "" {
		method = request.Method
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	defer resp.Body.Close()

	if d.Debug {
		var dump []byte
		dump, err = httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, nil, err
		}

		fmt.Printf("Received Response:\n%s\n\n", formatDump(dump, "< "))
	}

	body, _ := ioutil.ReadAll(resp.Body)

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

	return cReq, cRes, nil
}

var startLineRegex = regexp.MustCompile(`(?m)^`)

func formatDump(data []byte, prefix string) string {
	data = startLineRegex.ReplaceAllLiteral(data, []byte(prefix))
	return string(data)
}
