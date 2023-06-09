// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"context"
	"net/netip"
	"time"

	. "github.com/cilium/checkmate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientv1 "k8s.io/client-go/applyconfigurations/core/v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// fakeSender mocks the GARP Sender, allowing for a feedback channel.
type fakeSender struct {
	sent chan netip.Addr
}

func (ms *fakeSender) Send(ip netip.Addr) error {
	ms.sent <- ip
	return nil
}

func (s *garpSuite) TestProcessorCell(c *C) {
	testIfaceName := "lo"

	// These allow us to inspect the state of the processor cell.
	garpSent := make(chan netip.Addr)
	var processorState *map[resource.Key]netip.Addr

	_, cs := k8sClient.NewFakeClientset()

	h := hive.New(cell.Module(
		"test-garp-processor-cell",
		"TestProcessorCell",

		// Provide the mock k8s client cell.
		cell.Provide(func() k8sClient.Clientset { return cs }),

		// Provide the mock GARP Sender cell, passing in feedback
		// channel.
		cell.Provide(func() Sender { return &fakeSender{sent: garpSent} }),

		cell.Config(Config{}),

		localPodsCell,
		cell.Provide(newGARPProcessor),

		// Force invocation.
		cell.Invoke(func(ep Processor) {
			e, _ := ep.(*processor)
			c.Assert(e, NotNil)
			// Here we keep a reference to the internal pod IP state in
			// the parent scope so we can inspect later.
			processorState = &e.podIPsState
		}),
	))

	// Apply the config so that the GARP cell will initialise.
	hive.AddConfigOverride(h, func(cfg *Config) {
		cfg.L2PodAnnouncementsInterface = testIfaceName
		cfg.EnableL2PodAnnouncements = true
	})

	// Everything is ready, start the cell.
	if err := h.Start(context.Background()); err != nil {
		c.Fatalf("Failed to start: %s", err)
	}

	// getGARPEvent is a helper func to see if a GARP packet would have
	// been sent. This assumes that if a GARP event should have been
	// sent, it would happen within the timeout window. Returns nil if
	// no GARP packet is sent.
	getGARPEvent := func() *netip.Addr {
		select {
		case e := <-garpSent:
			return &e
		case <-time.After(5 * time.Second):
			return nil
		}
	}

	// checkState is a helper function that asserts that the GARP
	// processor state matches the given desired state.
	checkState := func(desired map[string]string) {
		c.Assert(*processorState, HasLen, len(desired))
		desiredState := make(map[resource.Key]netip.Addr)
		for name, ip := range desired {
			desiredState[resource.Key{Name: name, Namespace: "default"}] = netip.MustParseAddr(ip)
		}
		c.Assert(*processorState, checker.DeepEquals, desiredState)
	}

	// Create a Pod. This should sent a GARP packet, and should present
	// an item in the state.
	podOne := makePod(c, cs, "pod-1", "1.2.3.4")
	garpEvent := getGARPEvent()
	c.Assert(garpEvent, NotNil) // GARP packet sent
	c.Assert(garpEvent.String(), Equals, "1.2.3.4")
	checkState(map[string]string{"pod-1": "1.2.3.4"})

	// Update the previous Pod with the same IP. This should not send
	// any GARP packets or change the state.
	_ = updatePodIP(c, cs, podOne, "1.2.3.4")
	garpEvent = getGARPEvent()
	c.Assert(garpEvent, IsNil) // NO GARP packet sent
	checkState(map[string]string{"pod-1": "1.2.3.4"})

	// Update the previous Pod with a new IP. This should send a new
	// GARP packet and the state should reflect the new IP.
	_ = updatePodIP(c, cs, podOne, "4.3.2.1")
	garpEvent = getGARPEvent()
	c.Assert(garpEvent, NotNil) // GARP packet sent
	c.Assert(garpEvent.String(), Equals, "4.3.2.1")
	checkState(map[string]string{"pod-1": "4.3.2.1"})

	// Delete the previous Pod. This should not send any GARP packets,
	// and the pod should no longer be present in the state.
	deletePod(c, cs, "pod-1")
	garpEvent = getGARPEvent()
	c.Assert(garpEvent, IsNil) // NO GARP packet sent
	checkState(map[string]string{})
}

func (s *garpSuite) TestPodIPv4ParseFunc(c *C) {
	c.Assert(getPodIPv4([]corev1.PodIP{}), Equals, netip.Addr{})
	c.Assert(getPodIPv4([]corev1.PodIP{{IP: "::1"}}), Equals, netip.Addr{})
	c.Assert(getPodIPv4([]corev1.PodIP{{IP: "::1"}, {IP: "1.2.3.4"}}), Equals, netip.MustParseAddr("1.2.3.4"))
	c.Assert(getPodIPv4([]corev1.PodIP{{IP: "1.2.3.4"}, {IP: "::1"}}), Equals, netip.MustParseAddr("1.2.3.4"))
	c.Assert(getPodIPv4([]corev1.PodIP{{IP: "1.2.3.4"}}), Equals, netip.MustParseAddr("1.2.3.4"))
}

// makePod makes a test pod with the provided IP.
func makePod(c *C, cs k8sClient.Clientset, name string, ip string) *corev1.Pod {
	addr := netip.MustParseAddr(ip).String()

	podDefinition := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Status:     corev1.PodStatus{PodIP: addr, PodIPs: []corev1.PodIP{{IP: addr}}},
	}

	pod, err := cs.CoreV1().Pods("default").Create(context.Background(), &podDefinition, metav1.CreateOptions{})
	c.Assert(err, IsNil)

	return pod
}

// updatePodIP updates the status field of given pod with a new IP and applies it.
func updatePodIP(c *C, cs k8sClient.Clientset, pod *corev1.Pod, ip string) *corev1.Pod {
	addr := netip.MustParseAddr(ip).String()

	extractedPod, err := clientv1.ExtractPod(pod, "")
	c.Assert(err, IsNil)

	podStatusApply := clientv1.PodStatus().WithPodIP(addr).WithPodIPs(clientv1.PodIP().WithIP(addr))
	podApply := extractedPod.WithStatus(podStatusApply)

	updated, err := cs.CoreV1().Pods("default").ApplyStatus(context.Background(), podApply, metav1.ApplyOptions{})
	c.Assert(err, IsNil)

	return updated
}

// deletePod deletes the given pod.
func deletePod(c *C, cs k8sClient.Clientset, pod string) {
	err := cs.CoreV1().Pods("default").Delete(context.Background(), "pod-1", metav1.DeleteOptions{})
	c.Assert(err, IsNil)
}
