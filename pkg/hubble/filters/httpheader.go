// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"errors"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByHTTPHeader(h []*flowpb.HTTPHeader) (FilterFunc, error) {

	return func(ev *v1.Event) bool {
		for _, w := range ev.GetFlow().L7.GetHttp().GetHeaders() {
			for _, f := range h {
				if (f.GetKey() == "" || f.GetKey() == w.GetKey()) &&
					(f.GetValue() == "" || f.GetValue() == w.GetValue()) {
					return true
				}
			}
		}
		return false
	}, nil

}

// HTTPHeaderimplements filtering based on header

type HTTPHeaderFilter struct{}

func (*HTTPHeaderFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
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

	return fs, nil
}
