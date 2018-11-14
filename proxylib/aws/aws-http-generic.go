// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awsparsers

import (
	"bufio"
	"bytes"
	log "github.com/sirupsen/logrus"
	"net/http"
)

//
//  These are generic Utilities for parsing HTTP in golang parsers.
//  Longer term, we may want to pull these out of the aws package into
//  their own package or proxylib, as generally they are potentially useful
//  for all HTTP-based protocol parsing.

var HTTPAccessDeniedStr string = "HTTP/1.1 403 Access Denied\r\n\r\n"

// takes an array of bytes that may contain one or more raw HTTP requests
// and returns a http.Request object (or nil) and the length in bytes of the
// total request (header + body).  If nil, length will be 0 and last return value
// will be the number of additional bytes it needs to see before it may see the full request.
// Returns (nil, -1) on permement parsing error.
func parseHTTPRequest(data []byte) (*http.Request, int, int) {

	headerLen := 0
	for i := 0; i < len(data)-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			headerLen = i + 4
			break // exit at first end of header
		}
	}
	if headerLen == 0 {
		// don't have full header
		log.Infof("Don't have full header")
		return nil, 0, 1
	}
	bReader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(bReader)
	if err != nil {
		// malformed request
		return nil, 0, -1
	}
	totalReqLen := headerLen + int(req.ContentLength)
	if totalReqLen > len(data) {
		log.Infof("Have %d bytes, looking for full %d bytes", len(data), totalReqLen)
		return nil, 0, totalReqLen - len(data)
	}
	return req, totalReqLen, 0
}

// takes an array of bytes that may contain one or more raw HTTP responses (or
// partial responses)
// Returns the parsed http.Response and length of the first response.  If the
// buffer does not include a full HTTP header, length is -1.
// If buffer includes header but not full body, response is nil, length if the
// full response length.
func parseHTTPResponse(data []byte) (*http.Response, int) {

	headerLen := 0
	for i := 0; i < len(data)-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			headerLen = i + 4
			break // exit at first end of header
		}
	}
	if headerLen == 0 {
		// don't have full header
		log.Infof("Don't have full header")
		return nil, 1
	}
	bReader := bufio.NewReader(bytes.NewReader(data))
	res, err := http.ReadResponse(bReader, nil)
	if err != nil {
		// malformed request
		return nil, -1
	}
	totalResLen := headerLen + int(res.ContentLength)
	if totalResLen > len(data) {
		log.Infof("Have %d bytes, looking for full %d bytes", len(data), totalResLen)
		return nil, totalResLen
	}
	return res, totalResLen
}
