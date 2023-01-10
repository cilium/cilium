// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByReplyField(replyParams []bool) FilterFunc {
	return func(ev *v1.Event) bool {
		if len(replyParams) == 0 {
			return true
		}
		switch f := ev.Event.(type) {
		case *flowpb.Flow:
			// FIXME: For dropped flows, we handle `is_reply=unknown` as
			// `is_reply=false`. This is for compatibility with older clients
			// (such as Hubble UI) which assume this filter applies to the
			// deprecated `reply` field, where dropped flows always have
			// `reply=false`.
			if f.GetIsReply() == nil && f.GetVerdict() != flowpb.Verdict_DROPPED {
				return false
			}

			reply := f.GetIsReply().GetValue()
			for _, replyParam := range replyParams {
				if reply == replyParam {
					return true
				}
			}
		}
		return false
	}
}

// ReplyFilter implements filtering for reply flows
type ReplyFilter struct{}

// OnBuildFilter builds a reply filter
func (r *ReplyFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetReply() != nil {
		fs = append(fs, filterByReplyField(ff.GetReply()))
	}

	return fs, nil
}
