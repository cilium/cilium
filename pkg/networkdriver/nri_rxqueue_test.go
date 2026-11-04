// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

type rxQueueTestEndpoints map[string]*endpoint.Endpoint

func (e rxQueueTestEndpoints) LookupCNIAttachmentID(id string) *endpoint.Endpoint { return e[id] }

func TestNRIWithRXQueueAttachment(t *testing.T) {
	driver := buildNRIDriver(t)
	sandbox := podSandbox("pod", "/run/netns/pod")
	attachmentID := sandbox.Id + ":eth0"
	ep := &endpoint.Endpoint{
		K8sUID: "pod", NetNsCookie: 42,
		IPv4: netip.MustParseAddr("192.0.2.10"), IPv6: netip.MustParseAddr("2001:db8::10"),
	}
	endpoints := rxQueueTestEndpoints{}
	driver.endpoints = endpoints
	device := func(binding *rxqueue.RXQueueBinding) *rxqueue.RXQueueDevice {
		return &rxqueue.RXQueueDevice{
			PhysicalIfName: "ens1", Prepared: true, PodIfName: "eth0", ShareID: "share",
			PhysicalQueueID: 62, VirtualQueueID: 1, Binding: binding,
		}
	}
	wtxn := driver.db.WriteTxn(driver.allocationTable)
	driver.allocationTable.Insert(wtxn, &DRAAllocation{
		DeviceName: "ens1", LogicalPool: "rx-queues", Manager: types.DeviceManagerTypeRXQueue,
		PodUID: "pod", ClaimUID: "claim", ShareID: "share", PreparedDevice: device(nil),
	})
	wtxn.Commit()
	prepared := func() *rxqueue.RXQueueDevice {
		return driver.allocationsForPod("pod")[0].Device.(*rxqueue.RXQueueDevice)
	}

	oldOpen, oldCookie, oldBind := openPodNetNS, rxQueueNamespaceCookie, rxQueueBind
	t.Cleanup(func() {
		openPodNetNS, rxQueueNamespaceCookie, rxQueueBind = oldOpen, oldCookie, oldBind
	})
	openPodNetNS = func(string) (*netns.NetNS, error) { return &netns.NetNS{}, nil }
	cookie := uint64(42)
	rxQueueNamespaceCookie = func(*netns.NetNS) (uint64, error) { return cookie, nil }
	binds := 0
	generation := uint64(1)
	rxQueueBind = func(_ *rxqueue.RXQueueDevice, _ *netns.NetNS, id string, addresses []netip.Addr) (*rxqueue.RXQueueDevice, error) {
		binds++
		return device(&rxqueue.RXQueueBinding{AttachmentID: id, Generation: generation, Addresses: slices.Clone(addresses)}), nil
	}

	ctx := context.Background()
	require.ErrorContains(t, driver.RunPodSandbox(ctx, sandbox), "does not belong")
	endpoints[attachmentID] = ep
	ep.DatapathConfiguration.ExternalIpam = true
	require.ErrorContains(t, driver.RunPodSandbox(ctx, sandbox), "requires Cilium-managed IPAM")
	ep.DatapathConfiguration.ExternalIpam = false
	ep.K8sUID = "another-pod"
	require.ErrorContains(t, driver.RunPodSandbox(ctx, sandbox), "does not belong")
	ep.K8sUID = "pod"
	cookie++
	require.ErrorContains(t, driver.RunPodSandbox(ctx, sandbox), "different network namespace")
	require.Zero(t, binds)
	cookie = ep.NetNsCookie

	require.NoError(t, driver.RunPodSandbox(ctx, sandbox))
	require.Equal(t, []netip.Addr{ep.IPv4, ep.IPv6}, prepared().Binding.Addresses)
	require.Equal(t, uint64(1), prepared().Binding.Generation)
	_, err := driver.Synchronize(ctx, []*api.PodSandbox{sandbox}, nil)
	require.NoError(t, err)
	require.Equal(t, 2, binds)
	require.Equal(t, uint64(1), prepared().Binding.Generation)

	// The same Pod and claim acquire a replacement sandbox. Its endpoint is
	// authoritative even while the Kubernetes Pod still reports the old IPs.
	replacement := podSandbox("pod", "/run/netns/replacement")
	replacement.Id = "replacement"
	attachmentID = replacement.Id + ":eth0"
	endpoints[attachmentID] = &endpoint.Endpoint{K8sUID: "pod", NetNsCookie: 42, IPv4: netip.MustParseAddr("192.0.2.20")}
	generation++
	require.NoError(t, driver.RunPodSandbox(ctx, replacement))
	require.Equal(t, uint64(2), prepared().Binding.Generation)
	require.Equal(t, []netip.Addr{endpoints[attachmentID].IPv4}, prepared().Binding.Addresses)
	binding := *prepared().Binding
	binding.Addresses = slices.Clone(binding.Addresses)
	require.NoError(t, driver.StopPodSandbox(ctx, sandbox))
	require.Equal(t, &binding, prepared().Binding, "a delayed stop leaves the replacement binding unchanged")
	require.Contains(t, driver.podNetns, replacement.Id)

	// Stop removes the cached namespace. Address release withdraws steering.
	require.NoError(t, driver.StopPodSandbox(ctx, replacement))
	require.Equal(t, &binding, prepared().Binding)
	require.NotContains(t, driver.podNetns, replacement.Id)
	require.NoError(t, driver.StopPodSandbox(ctx, replacement))
	require.Equal(t, &binding, prepared().Binding)

	// RX allocations do not skip the ordinary interface cleanup path.
	wtxn = driver.db.WriteTxn(driver.allocationTable)
	driver.allocationTable.Insert(wtxn, &DRAAllocation{
		DeviceName: "dummy0", LogicalPool: "dummy", Manager: types.DeviceManagerTypeDummy,
		PodUID: "pod", ClaimUID: "other-claim", PreparedDevice: &dummy.DummyDevice{Name: "dummy0"},
	})
	wtxn.Commit()
	err = driver.StopPodSandbox(ctx, replacement)
	require.ErrorContains(t, err, "failed to open pinned netns")
}
