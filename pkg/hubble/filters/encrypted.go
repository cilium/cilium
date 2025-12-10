// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"slices"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByEncrypted(encryptedParams []bool) FilterFunc {
	return func(ev *v1.Event) bool {
		if len(encryptedParams) == 0 {
			return true
		}
		switch f := ev.Event.(type) {
		case *flowpb.Flow:
			encrypted := f.GetIP().GetEncrypted()
			return slices.Contains(encryptedParams, encrypted)
		}
		return false
	}
}

// EncryptedFilter implements filtering based on encryption status
type EncryptedFilter struct{}

// OnBuildFilter builds an encrypted filter
func (e *EncryptedFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetEncrypted() != nil {
		fs = append(fs, filterByEncrypted(ff.GetEncrypted()))
	}

	return fs, nil
}
