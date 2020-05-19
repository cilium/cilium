// Copyright 2019-2020 Authors of Hubble
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

package filters

import (
	"context"
	"errors"
	"fmt"
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
	httpStatusCodeFull   = regexp.MustCompile(`[1-5][0-9]{2}`)
	httpStatusCodePrefix = regexp.MustCompile(`^([1-5][0-9]?\+)$`)
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

	return fs, nil
}
