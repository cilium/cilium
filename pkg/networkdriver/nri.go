// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"

	"github.com/containerd/nri/pkg/api"
	"github.com/vishvananda/netlink"
	kube_types "k8s.io/apimachinery/pkg/types"
)

func getNetworkNamespace(pod *api.PodSandbox) string {
	// get the pod network namespace
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			return namespace.Path
		}
	}
	return ""
}

// RunPodSandbox is called by the container runtime when a pod sandbox is started.
// It configures the allocated network devices for the pod based on its network namespace.
func (driver *Driver) RunPodSandbox(ctx context.Context, podSandbox *api.PodSandbox) error {
	err := driver.withLock(func() error {
		l := driver.logger.With(
			logfields.K8sNamespace, podSandbox.GetNamespace(),
			logfields.K8sPodName, podSandbox.GetName(),
			logfields.UID, podSandbox.GetUid(),
		)

		l.DebugContext(ctx, "RunPodSandbox request received")

		networkNamespace := getNetworkNamespace(podSandbox)
		// host network pods cannot allocate network devices
		// nothing for us here
		if networkNamespace == "" {
			l.DebugContext(ctx, "RunPodSandbox pod using host network cannot claim host devices")
			return nil
		}

		l = l.With(logfields.NetNamespace, networkNamespace)

		alloc, ok := driver.allocations[kube_types.UID(podSandbox.Uid)]
		if !ok {
			l.DebugContext(ctx, "no allocation found")
			// allocation not found/doesn't exist
			return nil
		}

		nsPath := path.Join(defaults.NetNsPath, path.Base(networkNamespace))

		podNs, err := netns.OpenPinned(nsPath)
		if err != nil {
			return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
		}

		defer podNs.Close()

		for _, devices := range alloc {
			for _, a := range devices {
				l, err := safenetlink.LinkByName(a.Device.KernelIfName())
				if err != nil {
					return err
				}

				if err := netlink.LinkSetNsFd(l, podNs.FD()); err != nil {
					return err
				}

				if err := podNs.Do(func() error {
					if !a.Config.Empty() {
						if a.Config.Ipv4Addr != (netip.Prefix{}) {
							ip, n, err := net.ParseCIDR(a.Config.Ipv4Addr.String())
							if err == nil {
								if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: n.Mask}}); err != nil {
									return err
								}
							}
						}
					}
					if err := netlink.LinkSetUp(l); err != nil {
						return err
					}

					return nil
				}); err != nil {
					return err
				}
			}
		}

		return nil
	})

	return err
}

// StopPodSandbox is called when a pod sandbox is stopped.
// It cleans up the allocated network devices for the pod.
func (driver *Driver) StopPodSandbox(ctx context.Context, podSandbox *api.PodSandbox) error {
	err := driver.withLock(func() error {
		l := driver.logger.With(
			logfields.K8sNamespace, podSandbox.GetNamespace(),
			logfields.K8sPodName, podSandbox.GetName(),
			logfields.UID, podSandbox.GetUid(),
		)

		l.DebugContext(ctx, "StopPodSandbox request received")

		networkNamespace := getNetworkNamespace(podSandbox)
		// host network pods cannot allocate network devices because it impacts the host
		if networkNamespace == "" {
			l.DebugContext(ctx, "StopPodSandbox pod using host network cannot claim host devices")
			return nil
		}

		l = l.With(logfields.NetNamespace, networkNamespace)

		alloc, ok := driver.allocations[kube_types.UID(podSandbox.Uid)]
		if !ok {
			l.DebugContext(ctx, "no allocation found")
			// allocation not found/doesn't exist
			return nil
		}

		nsPath := path.Join(defaults.NetNsPath, path.Base(networkNamespace))

		podNs, err := netns.OpenPinned(nsPath)
		if err != nil {
			return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
		}

		defer podNs.Close()

		for _, devices := range alloc {
			if err := podNs.Do(func() error {
				for _, a := range devices {
					l, err := safenetlink.LinkByName(a.Device.KernelIfName())
					if err != nil {
						return err
					}

					if err := netlink.LinkSetDown(l); err != nil {
						return err
					}

					if err := netlink.LinkSetNsFd(l, 1); err != nil {
						return err
					}
				}

				return nil
			}); err != nil {
				return err
			}
		}

		return nil
	})

	return err
}
