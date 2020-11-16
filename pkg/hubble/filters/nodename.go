// Copyright 2020 Authors of Hubble
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
