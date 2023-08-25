// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"fmt"
	"net/url"
	"sort"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func decodeHTTP(flowType accesslog.FlowType, http *accesslog.LogRecordHTTP, opts *options.Options) *flowpb.Layer7_Http {
	var headers []*flowpb.HTTPHeader
	keys := make([]string, 0, len(http.Headers))
	for key := range http.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range http.Headers[key] {
			headers = append(headers, &flowpb.HTTPHeader{Key: key, Value: value})
		}
	}
	uri, _ := url.Parse(http.URL.String())
	var urlString string
	if uri != nil {
		if uri.User != nil {
			// Don't include the password in the flow.
			if _, ok := uri.User.Password(); ok {
				uri.User = url.UserPassword(uri.User.Username(), defaults.SensitiveValueRedacted)
			}
		}
		if opts.RedactHTTPQuery {
			uri.RawQuery = ""
			uri.Fragment = ""
		}
		urlString = uri.String()
	}
	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return &flowpb.Layer7_Http{
			Http: &flowpb.HTTP{
				Method:   http.Method,
				Protocol: http.Protocol,
				Url:      urlString,
				Headers:  headers,
			},
		}
	}

	return &flowpb.Layer7_Http{
		Http: &flowpb.HTTP{
			Code:     uint32(http.Code),
			Method:   http.Method,
			Protocol: http.Protocol,
			Url:      urlString,
			Headers:  headers,
		},
	}
}

func (p *Parser) httpSummary(flowType accesslog.FlowType, http *accesslog.LogRecordHTTP, flow *flowpb.Flow) string {
	httpRequest := fmt.Sprintf("%s %s", http.Method, http.URL)
	switch flowType {
	case accesslog.TypeRequest:
		return fmt.Sprintf("%s %s", http.Protocol, httpRequest)
	case accesslog.TypeResponse:
		return fmt.Sprintf("%s %d %dms (%s)", http.Protocol, http.Code, uint64(time.Duration(flow.GetL7().LatencyNs)/time.Millisecond), httpRequest)
	}
	return ""
}
