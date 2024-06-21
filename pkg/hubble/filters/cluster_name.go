// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func sourceClusterName(ev *v1.Event) string {
	return ev.GetFlow().GetSource().GetClusterName()
}

func destinationClusterName(ev *v1.Event) string {
	return ev.GetFlow().GetDestination().GetClusterName()
}

func filterByClusterName(names []string, getClusterName func(*v1.Event) string) (FilterFunc, error) {
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("invalid filter, name must not be empty")
		}
	}

	return func(ev *v1.Event) bool {
		target := getClusterName(ev)
		for _, n := range names {
			if n == target {
				return true
			}
		}

		return false
	}, nil
}

// ClusterNameFilter implements filtering based on endpoint cluster name.
type ClusterNameFilter struct{}

// OnBuildFilter builds a Hubble endpoint cluster name filter.
func (_ *ClusterNameFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if names := ff.GetSourceClusterName(); names != nil {
		f, err := filterByClusterName(names, sourceClusterName)
		if err != nil {
			return nil, err
		}
		fs = append(fs, f)
	}

	if names := ff.GetDestinationClusterName(); names != nil {
		f, err := filterByClusterName(names, destinationClusterName)
		if err != nil {
			return nil, err
		}
		fs = append(fs, f)
	}

	return fs, nil
}
