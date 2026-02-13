// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/ir"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
)

func decodeHTTP(flowType accesslog.FlowType, http *accesslog.LogRecordHTTP, opts *options.Options) ir.HTTP {
	var headers []ir.HTTPHeader
	if len(http.Headers) > 0 {
		headers = make([]ir.HTTPHeader, 0, len(http.Headers))
	}
	for _, key := range slices.Sorted(maps.Keys(http.Headers)) {
		for _, value := range http.Headers[key] {
			filteredValue := filterHeader(key, value, opts.HubbleRedactSettings)
			headers = append(headers, ir.HTTPHeader{Key: key, Value: filteredValue})
		}
	}
	uri := filteredURL(http.URL, opts.HubbleRedactSettings)

	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return ir.HTTP{
			Method:   http.Method,
			Protocol: http.Protocol,
			URL:      uri.String(),
			Headers:  headers,
		}
	}

	return ir.HTTP{
		Code:     uint32(http.Code),
		Method:   http.Method,
		Protocol: http.Protocol,
		URL:      uri.String(),
		Headers:  headers,
	}
}

func (p *Parser) httpSummary(flowType accesslog.FlowType, http *accesslog.LogRecordHTTP, flow *ir.Flow) string {
	uri := filteredURL(http.URL, p.opts.HubbleRedactSettings)
	switch flowType {
	case accesslog.TypeRequest:
		return http.Protocol + " " + http.Method + " " + uri.String()
	case accesslog.TypeResponse:
		return http.Protocol + " " + strconv.Itoa(http.Code) + " " + strconv.FormatUint(uint64(time.Duration(flow.L7.LatencyNs)/time.Millisecond), 10) + "ms " + http.Method + " " + uri.String()
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

// filteredURL return a copy of the given URL potentially mutated depending on
// Hubble redact settings.
// If configured and user info exists, it removes the password from the flow.
// If configured, it removes the URL's query parts from the flow.
func filteredURL(uri *url.URL, redactSettings options.HubbleRedactSettings) (u url.URL) {
	if uri == nil {
		// NOTE: return a non-nil URL so that we can always call String() on
		// it.
		return
	}
	u2 := cloneURL(uri)
	if redactSettings.RedactHTTPUserInfo && u2.User != nil {
		if _, ok := u2.User.Password(); ok {
			u2.User = url.UserPassword(u2.User.Username(), defaults.SensitiveValueRedacted)
		}
	}
	if redactSettings.RedactHTTPQuery {
		u2.RawQuery = ""
		u2.Fragment = ""
	}
	return *u2
}

// cloneURL return a copy of the given URL. Copied from src/net/http/clone.go.
func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}
