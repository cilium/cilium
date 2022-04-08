// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/monitor/api"
)

func httpMatchCompatibleEventFilter(types []*flowpb.EventTypeFilter) bool {
	if len(types) == 0 {
		return true
	}

	for _, t := range types {
		if t.GetType() == api.MessageTypeAccessLog {
			return true
		}
	}

	return false
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
		for _, f := range full {
			if httpStatusCode == f {
				return true
			}
		}
		for _, p := range prefix {
			if strings.HasPrefix(httpStatusCode, p) {
				return true
			}
		}

		return false
	}, nil
}

func filterByHTTPMethods(methods []string) (FilterFunc, error) {
	return func(ev *v1.Event) bool {
		http := ev.GetFlow().GetL7().GetHttp()

		if http == nil || http.Method == "" {
			// Not an HTTP or method is missing
			return false
		}

		for _, method := range methods {
			if strings.EqualFold(http.Method, method) {
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
			return nil, fmt.Errorf("%s: %v", pathRegexpStr, err)
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
		for _, pathRegexp := range pathRegexps {
			if pathRegexp.MatchString(uri.Path) {
				return true
			}
		}

		return false
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
			return nil, fmt.Errorf("invalid http status code filter: %v", err)
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
			return nil, fmt.Errorf("invalid http method filter: %v", err)
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
			return nil, fmt.Errorf("invalid http path filter: %v", err)
		}
		fs = append(fs, pathf)
	}

	return fs, nil
}
