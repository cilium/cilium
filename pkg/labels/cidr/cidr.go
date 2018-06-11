// Copyright 2018 Authors of Cilium
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

package cidr

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
)

// GetCIDRLabels turns a CIDR into a set of labels representing the cidr itself
// and all broader CIDRS which include the specified CIDR in them. For example:
// CIDR: 10.0.0.0/8 =>
//     "cidr:10.0.0.0/8", "cidr:10.0.0.0/7", "cidr:8.0.0.0/6",
//     "cidr:8.0.0.0/5", "cidr:0.0.0.0/4, "cidr:0.0.0.0/3",
//     "cidr:0.0.0.0/2",  "cidr:0.0.0.0/1",  "cidr:0.0.0.0/0"
// (plus one of reserved:cluster or reserved:world, depending on whether the
// cluster falls within the IP range of the cluster or not)
func GetCIDRLabels(cidr *net.IPNet) labels.Labels {
	ones, bits := cidr.Mask.Size()
	result := []string{}

	// If ones is zero, then it's the default CIDR prefix /0 which should
	// just be regarded as reserved:world. In all other cases, we need
	// to generate the set of prefixes starting from the /0 up to the
	// specified prefix length.
	if ones > 0 {
		for i := 0; i <= ones; i++ {
			label := labels.MaskedIPNetToLabelString(cidr, i, bits)
			result = append(result, label)
		}
	}

	var cluster *net.IPNet
	if cidr.IP.To4() == nil {
		cluster = node.GetIPv6ClusterRange()
	} else {
		cluster = node.GetIPv4ClusterRange()
	}

	var label string
	clusterSize, _ := cluster.Mask.Size()
	if cluster.Contains(cidr.IP) && clusterSize <= ones {
		label = fmt.Sprintf("%s:%s", labels.LabelSourceReserved, labels.IDNameCluster)
	} else {
		label = fmt.Sprintf("%s:%s", labels.LabelSourceReserved, labels.IDNameWorld)
	}
	result = append(result, label)

	return labels.NewLabelsFromModel(result)
}
