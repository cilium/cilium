// Copyright 2016-2020 Authors of Cilium
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

// +build !privileged_tests

package k8s

import (
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"

	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
)

func (s *K8sSuite) TestUseNodeCIDR(c *C) {
	// Test IPv4
	node1 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "10.2.0.0/16",
		},
	}

	// set buffer to 2 to prevent blocking when calling UseNodeCIDR
	// and we need to wait for the response of the channel.
	patchStatusChan := make(chan bool, 2)
	fakeK8sClient := &fake.Clientset{}
	k8sCli.Interface = fakeK8sClient
	fakeK8sClient.AddReactor("patch", "nodes",
		func(action testing.Action) (bool, runtime.Object, error) {
			if action.GetSubresource() != "status" {
				return true, nil, nil
			}

			patchReceived := action.(testing.PatchAction).GetPatch()
			if !strings.Contains(string(patchReceived), `"status":"False"`) {
				c.Errorf("PatchStatus() did not patch \"status\":\"False\"")
				c.FailNow()
			}
			patchStatusChan <- true
			return true, node1.DeepCopy(), nil
		})

	node1Slim := ConvertToNode(node1.DeepCopy()).(*types.Node)
	node1Cilium := ParseNode(node1Slim, source.Unspec)

	useNodeCIDR(node1Cilium)
	c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.2.0.0/16")
	// IPv6 Node range is not checked because it shouldn't be changed.

	k8sCli.SetNodeNetworkUnavailableFalse("node1")

	select {
	case <-patchStatusChan:
	case <-time.Tick(10 * time.Second):
		c.Errorf("d.fakeK8sClient.CoreV1().Nodes().PatchStatus() was not called")
		c.FailNow()
	}

	// Test IPv6
	node2 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				annotation.V4CIDRName: "10.254.0.0/16",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "aaaa:aaaa:aaaa:aaaa:beef:beef::/96",
		},
	}

	node2Slim := ConvertToNode(node2.DeepCopy()).(*types.Node)
	node2Cilium := ParseNode(node2Slim, source.Unspec)
	useNodeCIDR(node2Cilium)

	// We use the node's annotation for the IPv4 and the PodCIDR for the
	// IPv6.
	c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.254.0.0/16")
	c.Assert(node.GetIPv6AllocRange().String(), Equals, "aaaa:aaaa:aaaa:aaaa:beef:beef::/96")
}
