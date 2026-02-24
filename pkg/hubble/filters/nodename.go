// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

// filterByNodeNames returns a function that filters flow events based on the
// node name.
func filterByNodeNames(nodeNames []string) (FilterFunc, error) {
	nodeNameRegexp, err := compileNodeNamePattern(nodeNames)
	if err != nil {
		return nil, err
	}

	return func(ev *v1.Event) bool {
		nodeName := ev.GetFlow().GetNodeName()
		if nodeName == "" {
			return false
		}
		// ensure that the node name always includes a cluster name
		if strings.IndexByte(nodeName, '/') == -1 {
			nodeName = ciliumDefaults.ClusterName + "/" + nodeName
		}
		return nodeNameRegexp.MatchString(nodeName)
	}, nil
}

// A NodeNameFilter filters on node name.
type NodeNameFilter struct{}

// OnBuildFilter builds a node name filter.
func (n *NodeNameFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetNodeName() != nil {
		nodeNameF, err := filterByNodeNames(ff.GetNodeName())
		if err != nil {
			return nil, err
		}
		fs = append(fs, nodeNameF)
	}

	return fs, nil
}
