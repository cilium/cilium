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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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
				annotation.V4CIDRName:   "10.254.0.0/16",
				annotation.CiliumHostIP: "10.254.0.1",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "10.2.0.0/16",
		},
	}

	// set buffer to 2 to prevent blocking when calling UseNodeCIDR
	// and we need to wait for the response of the channel.
	patchChan := make(chan bool, 2)
	fakeK8sClient := &fake.Clientset{}
	k8sCli.Interface = fakeK8sClient
	fakeK8sClient.AddReactor("patch", "nodes",
		func(action testing.Action) (bool, runtime.Object, error) {
			// If subresource is empty it means we are patching status and not
			// patching annotations
			if action.GetSubresource() != "" {
				return true, nil, nil
			}

			n1copy := node1.DeepCopy()
			n1copy.Annotations[annotation.V4CIDRName] = "10.2.0.0/16"
			raw, err := json.Marshal(n1copy.Annotations)
			if err != nil {
				c.Assert(err, IsNil)
			}
			patchWanted := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))

			patchReceived := action.(testing.PatchAction).GetPatch()
			c.Assert(string(patchReceived), checker.DeepEquals, string(patchWanted))
			patchChan <- true
			return true, n1copy, nil
		})

	node1Slim := ConvertToNode(node1.DeepCopy()).(*slim_corev1.Node)
	node1Cilium := ParseNode(node1Slim, source.Unspec)

	useNodeCIDR(node1Cilium)
	c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.2.0.0/16")
	// IPv6 Node range is not checked because it shouldn't be changed.

	err := k8sCli.AnnotateNode("node1",
		0,
		node.GetIPv4AllocRange(),
		node.GetIPv6AllocRange(),
		nil,
		nil,
		net.ParseIP("10.254.0.1"),
		net.ParseIP(""))

	c.Assert(err, IsNil)

	select {
	case <-patchChan:
	case <-time.Tick(10 * time.Second):
		c.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
		c.FailNow()
	}

	// Test IPv6
	node2 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				annotation.V4CIDRName:   "10.254.0.0/16",
				annotation.CiliumHostIP: "10.254.0.1",
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "aaaa:aaaa:aaaa:aaaa:beef:beef::/96",
		},
	}

	failAttempts := 0

	fakeK8sClient = &fake.Clientset{}
	k8sCli.Interface = fakeK8sClient
	fakeK8sClient.AddReactor("patch", "nodes",
		func(action testing.Action) (bool, runtime.Object, error) {
			// If subresource is empty it means we are patching status and not
			// patching annotations
			if action.GetSubresource() != "" {
				return true, nil, nil
			}
			// first call will be a patch for annotations
			if failAttempts == 0 {
				failAttempts++
				return true, nil, fmt.Errorf("failing on purpose")
			}
			n2Copy := node2.DeepCopy()
			n2Copy.Annotations[annotation.V4CIDRName] = "10.254.0.0/16"
			n2Copy.Annotations[annotation.V6CIDRName] = "aaaa:aaaa:aaaa:aaaa:beef:beef::/96"
			raw, err := json.Marshal(n2Copy.Annotations)
			if err != nil {
				c.Assert(err, IsNil)
			}
			patchWanted := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))

			patchReceived := action.(testing.PatchAction).GetPatch()
			c.Assert(string(patchReceived), checker.DeepEquals, string(patchWanted))
			patchChan <- true
			return true, n2Copy, nil
		})

	node2Slim := ConvertToNode(node2.DeepCopy()).(*slim_corev1.Node)
	node2Cilium := ParseNode(node2Slim, source.Unspec)
	useNodeCIDR(node2Cilium)

	// We use the node's annotation for the IPv4 and the PodCIDR for the
	// IPv6.
	c.Assert(node.GetIPv4AllocRange().String(), Equals, "10.254.0.0/16")
	c.Assert(node.GetIPv6AllocRange().String(), Equals, "aaaa:aaaa:aaaa:aaaa:beef:beef::/96")

	err = k8sCli.AnnotateNode("node2",
		0,
		node.GetIPv4AllocRange(),
		node.GetIPv6AllocRange(),
		nil,
		nil,
		net.ParseIP("10.254.0.1"),
		net.ParseIP(""))

	c.Assert(err, IsNil)

	select {
	case <-patchChan:
	case <-time.Tick(10 * time.Second):
		c.Errorf("d.fakeK8sClient.CoreV1().Nodes().Update() was not called")
		c.FailNow()
	}
}

func (s *K8sSuite) Test_runHeartbeat(c *C) {
	// k8s api server never replied back in the expected time. We should close all connections
	k8smetrics.LastSuccessInteraction.Reset()
	time.Sleep(2 * time.Millisecond)

	testCtx, testCtxCancel := context.WithCancel(context.Background())

	called := make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			// Block any attempt to connect return from a heartbeat until the
			// test is complete.
			<-testCtx.Done()
			return nil
		},
		time.Millisecond,
		func() {
			close(called)
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err := testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))
	testCtxCancel()

	// There are some connectivity issues, cilium is trying to reach kube-apiserver
	// but it's only receiving errors for other requests. We should close all
	// connections!

	// Wait the double amount of time than the timeout to make sure
	// LastSuccessInteraction is not taken into account and we will see that we
	// will close all connections.
	testCtx, testCtxCancel = context.WithCancel(context.Background())
	time.Sleep(200 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			// Block any attempt to connect return from a heartbeat until the
			// test is complete.
			<-testCtx.Done()
			return nil
		},
		100*time.Millisecond,
		func() {
			close(called)
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err = testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))
	testCtxCancel()

	// Cilium is successfully talking with kube-apiserver, we should not do
	// anything.
	k8smetrics.LastSuccessInteraction.Reset()

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		100*time.Millisecond,
		func() {
			c.Error("This should not have been called!")
		},
	)

	select {
	case <-time.After(200 * time.Millisecond):
	case <-called:
		c.Error("Heartbeat should have closed all connections")
	}

	// Cilium had the last interaction with kube-apiserver a long time ago.
	// We should perform a heartbeat
	k8smetrics.LastInteraction.Reset()
	time.Sleep(500 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		100*time.Millisecond,
		func() {
			c.Error("This should not have been called!")
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err = testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))

	// Cilium had the last interaction with kube-apiserver a long time ago.
	// We should perform a heartbeat but the heart beat will return
	// an error so we should close all connections
	k8smetrics.LastInteraction.Reset()
	time.Sleep(500 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			return &errors.StatusError{
				ErrStatus: metav1.Status{
					Code: http.StatusRequestTimeout,
				},
			}
		},
		100*time.Millisecond,
		func() {
			close(called)
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err = testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))
}
