// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package aggregator

import (
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
)

// AggregateStatus computes the aggregate status for all the resources.
// The rules are the following:
//   - If any of the resources has the FailedStatus, the aggregate status is also
//     FailedStatus
//   - If none of the resources have the FailedStatus and at least one is
//     UnknownStatus, the aggregate status is UnknownStatus
//   - If all the resources have the desired status, the aggregate status is the
//     desired status.
//   - If none of the first three rules apply, the aggregate status is
//     InProgressStatus
func AggregateStatus(rss []*event.ResourceStatus, desired status.Status) status.Status {
	if len(rss) == 0 {
		return desired
	}

	allDesired := true
	anyUnknown := false
	for _, rs := range rss {
		s := rs.Status
		if s == status.FailedStatus {
			return status.FailedStatus
		}
		if s == status.UnknownStatus {
			anyUnknown = true
		}
		if s != desired {
			allDesired = false
		}
	}
	if anyUnknown {
		return status.UnknownStatus
	}
	if allDesired {
		return desired
	}
	return status.InProgressStatus
}
