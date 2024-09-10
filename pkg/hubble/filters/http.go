// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/monitor/api"
)

func httpMatchCompatibleEventFilter(types []*flowpb.EventTypeFilter) bool {
	if len(types) == 0 {
		return true
	}

	return slices.ContainsFunc(types, func(t *flowpb.EventTypeFilter) bool {
		return t.GetType() == api.MessageTypeAccessLog
	})
}

var (
	httpStatusCodeFull   = regexp.MustCompile(`^[1-5][0-9]{2}$`)
	httpStatusCodePrefix = regexp.MustCompile(`^[1-5][0-9]?\+$`)
)

func filterByHTTPStatusCode(statusCodePrefixes []string) (FilterFunc, error) {
	var full, prefix []string
	for _, s := range statusCodePrefixes {
		switch {
		case httpStatusCodeFull.MatchString(s):
			full = append(full, s)
		case httpStatusCodePrefix.MatchString(s):
			prefix = append(prefix, strings.TrimSuffix(s, "+"))
		default:
			return nil, fmt.Errorf("invalid status code prefix: %q", s)
		}
	}

	return func(ev *v1.Event) bool {
		http := ev.GetFlow().GetL7().GetHttp()
		// Not an HTTP response record
		if http == nil || http.Code == 0 {
			return false
		}

		// Check for both full matches or prefix matches
		httpStatusCode := fmt.Sprintf("%03d", http.Code)
		if slices.Contains(full, httpStatusCode) {
			return true
		}
		return slices.ContainsFunc(prefix, func(p string) bool {
			return strings.HasPrefix(httpStatusCode, p)
		})
	}, nil
}

func filterByHTTPMethods(methods []string) (FilterFunc, error) {
	return func(ev *v1.Event) bool {
		http := ev.GetFlow().GetL7().GetHttp()

		if http == nil || http.Method == "" {
			// Not an HTTP or method is missing
			return false
		}

		return slices.ContainsFunc(methods, func(method string) bool {
			return strings.EqualFold(http.Method, method)
		})
	}, nil
}

func filterByHTTPUrls(urlRegexpStrs []string) (FilterFunc, error) {
	urlRegexps := make([]*regexp.Regexp, 0, len(urlRegexpStrs))
	for _, urlRegexpStr := range urlRegexpStrs {
		urlRegexp, err := regexp.Compile(urlRegexpStr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", urlRegexpStr, err)
		}
		urlRegexps = append(urlRegexps, urlRegexp)
	}

	return func(ev *v1.Event) bool {
		http := ev.GetFlow().GetL7().GetHttp()

		if http == nil || http.Url == "" {
			return false
		}

		return slices.ContainsFunc(urlRegexps, func(urlRegexp *regexp.Regexp) bool {
			return urlRegexp.MatchString(http.Url)
		})
	}, nil
}

func filterByHTTPHeaders(headers []*flowpb.HTTPHeader) (FilterFunc, error) {
	return func(ev *v1.Event) bool {
		http := ev.GetFlow().GetL7().GetHttp()

		if http == nil || http.GetHeaders() == nil {
			// Not an HTTP or headers are missing
			return false
		}

		for _, httpHeader := range http.GetHeaders() {
			if slices.ContainsFunc(headers, func(header *flowpb.HTTPHeader) bool {
				return header.Key == httpHeader.Key && header.Value == httpHeader.Value
			}) {
				return true
			}
		}

		return false
	}, nil
}

func filterByHTTPPaths(pathRegexpStrs []string) (FilterFunc, error) {
	pathRegexps := make([]*regexp.Regexp, 0, len(pathRegexpStrs))
	for _, pathRegexpStr := range pathRegexpStrs {
		pathRegexp, err := regexp.Compile(pathRegexpStr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pathRegexpStr, err)
		}
		pathRegexps = append(pathRegexps, pathRegexp)
	}

	return func(ev *v1.Event) bool {
		http := ev.GetFlow().GetL7().GetHttp()

		if http == nil || http.Url == "" {
			return false
		}

		uri, err := url.ParseRequestURI(http.Url)
		if err != nil {
			// Silently drop all invalid URIs as there is nothing else we can
			// do.
			return false
		}
		return slices.ContainsFunc(pathRegexps, func(pathRegexp *regexp.Regexp) bool {
			return pathRegexp.MatchString(uri.Path)
		})
	}, nil
}

// HTTPFilter implements filtering based on HTTP metadata
type HTTPFilter struct{}

// OnBuildFilter builds a HTTP filter
func (h *HTTPFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetHttpStatusCode() != nil {
		if !httpMatchCompatibleEventFilter(ff.GetEventType()) {
			return nil, errors.New("filtering by http status code requires " +
				"the event type filter to only match 'l7' events")
		}

		hsf, err := filterByHTTPStatusCode(ff.GetHttpStatusCode())
		if err != nil {
			return nil, fmt.Errorf("invalid http status code filter: %w", err)
		}
		fs = append(fs, hsf)
	}

	if ff.GetHttpMethod() != nil {
		if !httpMatchCompatibleEventFilter(ff.GetEventType()) {
			return nil, errors.New("filtering by http method requires " +
				"the event type filter to only match 'l7' events")
		}

		methodf, err := filterByHTTPMethods(ff.GetHttpMethod())
		if err != nil {
			return nil, fmt.Errorf("invalid http method filter: %w", err)
		}
		fs = append(fs, methodf)
	}

	if ff.GetHttpPath() != nil {
		if !httpMatchCompatibleEventFilter(ff.GetEventType()) {
			return nil, errors.New("filtering by http path requires " +
				"the event type filter to only match 'l7' events")
		}

		pathf, err := filterByHTTPPaths(ff.GetHttpPath())
		if err != nil {
			return nil, fmt.Errorf("invalid http path filter: %w", err)
		}
		fs = append(fs, pathf)
	}

	if ff.GetHttpUrl() != nil {
		if !httpMatchCompatibleEventFilter(ff.GetEventType()) {
			return nil, errors.New("filtering by http url requires " +
				"the event type filter to only match 'l7' events")
		}

		pathf, err := filterByHTTPUrls(ff.GetHttpUrl())
		if err != nil {
			return nil, fmt.Errorf("invalid http url filter: %w", err)
		}
		fs = append(fs, pathf)
	}

	if ff.GetHttpHeader() != nil {
		if !httpMatchCompatibleEventFilter(ff.GetEventType()) {
			return nil, errors.New("filtering by http headers requires " +
				"the event type filter to only match 'l7' events")
		}

		headerf, err := filterByHTTPHeaders(ff.GetHttpHeader())
		if err != nil {
			return nil, fmt.Errorf("invalid http header filter: %w", err)
		}
		fs = append(fs, headerf)
	}

	return fs, nil
}
