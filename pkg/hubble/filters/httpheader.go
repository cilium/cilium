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

func filterByHTTPHeader(h []*flowpb.HTTPHeader,gethttp func(*v1.Event) *flowpb.HTTP) (FilterFunc, error) {

	return func(ev *v1.Event) bool {
		for _, w := range gethttp(ev).GetHeaders() {
			for _, f := range h {
				if (f.GetKey() == "" || f.GetKey() == w.GetKey()) &&
					(f.GetValue() == "" || f.GetValue() == w.GetValue()) {
					return true
				}
			}
		}
		return false
	}

}

// HTTPHeaderimplements filtering based on endpoint workload

type HTTPHeader struct{}

func (*HTTPHeader) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error)
{
	var fs []FilterFunc
    if ff.GetHttpHeader() != nil {	
		if !httpMatchCompatibleEventFilter(ff.GetEventType()) {
			return nil, errors.New("filtering by http headers requires " +
				"the event type filter to only match 'l7' events")
		}
		hh, err := filterByHTTPHeader(ff.GetHttpHeader())
		if err != nil {
			return nil, fmt.Errorf("invalid http header filter: %v", err)
		}
		fs = append(fs, hh)
	}
}
