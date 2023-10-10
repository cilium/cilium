// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
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
			filteredValue := filterHeader(key, value, opts.HubbleRedactSettings)
			headers = append(headers, &flowpb.HTTPHeader{Key: key, Value: filteredValue})
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
		if opts.HubbleRedactSettings.RedactHTTPQuery {
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
	uri, _ := url.Parse(http.URL.String())
	if p.opts.HubbleRedactSettings.RedactHTTPQuery {
		uri.RawQuery = ""
		uri.Fragment = ""
	}
	httpRequest := http.Method + " " + uri.String()
	switch flowType {
	case accesslog.TypeRequest:
		return fmt.Sprintf("%s %s", http.Protocol, httpRequest)
	case accesslog.TypeResponse:
		return fmt.Sprintf("%s %d %dms (%s)", http.Protocol, http.Code, uint64(time.Duration(flow.GetL7().LatencyNs)/time.Millisecond), httpRequest)
	}
	return ""
}

// filterHeader receives a key-value pair of an http header along with an HubbleRedactSettings.
// Based on the allow/deny lists of the provided HttpHeadersList it returns the original value
// or the redacted constant "HUBBLE_REDACTED" accordingly:
//  1. If HubbleRedactSettings is enabled (meaning that hubble.redact feature is enabled) but both allow/deny lists are empty then the value of the
//     header is redacted by default.
//  2. If the header's key is contained in the allow list then the value
//     of the header will not be redacted.
//  3. If the header's key is contained in the deny list then the value
//     of the header will be redacted.
//  4. If none of the above happens, then if there is any allow list defined then the value will be redacted
//     otherwise if there is a deny list defined the value will not be redacted.
func filterHeader(key string, value string, redactSettings options.HubbleRedactSettings) string {
	if !redactSettings.Enabled {
		return value
	}
	if len(redactSettings.RedactHttpHeaders.Allow) == 0 && len(redactSettings.RedactHttpHeaders.Deny) == 0 {
		// That's the default case, where redact is generally enabled but not headers' lists
		// have been specified. In that case we redact everything by default.
		return defaults.SensitiveValueRedacted
	}
	if _, ok := redactSettings.RedactHttpHeaders.Allow[strings.ToLower(key)]; ok {
		return value
	}
	if _, ok := redactSettings.RedactHttpHeaders.Deny[strings.ToLower(key)]; ok {
		return defaults.SensitiveValueRedacted
	}

	if len(redactSettings.RedactHttpHeaders.Allow) > 0 {
		return defaults.SensitiveValueRedacted
	}
	return value
}
