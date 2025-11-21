// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dra

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/containerd/nri/pkg/api"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
)

// FIXME: this is specific to dummy devices.
// Generally speaking, the NRI plugin logic should be device-dependant.

func (driver *Driver) RunPodSandbox(ctx context.Context, podSandbox *api.PodSandbox) error {
	netNs := podNetworkNamespace(podSandbox)
	// host network pods cannot allocate network devices because it impacts the host
	if netNs == "" {
		return fmt.Errorf("RunPodSandbox pod %s/%s using host network cannot claim host devices", podSandbox.Namespace, podSandbox.Name)
	}

	podUID := types.UID(podSandbox.Uid)
	driver.lock.Lock()
	allocatedDevices := driver.podDeviceConfig[podUID]
	driver.lock.Unlock()

	if len(allocatedDevices) == 0 {
		driver.logger.DebugContext(ctx, "No network devices allocated to pod",
			logfields.K8sNamespace, podSandbox.Namespace,
			logfields.Name, podSandbox.Name,
		)
		return nil
	}

	for _, allocatedDevice := range allocatedDevices {
		err := driver.configureDeviceForPod(ctx, allocatedDevice, podSandbox)
		if err != nil {
			driver.logger.ErrorContext(ctx, "Failed to configure device for pod",
				logfields.Error, err,
				logfields.Device, allocatedDevice.Name,
				logfields.K8sNamespace, podSandbox.Namespace,
				logfields.Name, podSandbox.Name,
				logfields.NetNamespace, netNs)
			return fmt.Errorf("failed to configure device %s for pod %s/%s: %w",
				allocatedDevice.Name, podSandbox.Namespace, podSandbox.Name, err)
		}

		driver.logger.DebugContext(ctx, "Successfully configured device device for pod",
			logfields.Device, allocatedDevice.Name,
			logfields.K8sNamespace, podSandbox.Namespace,
			logfields.Name, podSandbox.Name,
			logfields.NetNamespace, netNs)
	}

	return nil
}

func (driver *Driver) configureDeviceForPod(ctx context.Context, device AllocatedDevice, podSandbox *api.PodSandbox) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to get links: %w", err)
	}

	var (
		link  netlink.Link
		found bool
	)

	for _, l := range links {
		if l.Attrs().Name == device.Name {
			link = l
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("failed to find device %s", device.Name)
	}

	// fetch interface IP addresses
	addrs, err := safenetlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get dummy device %s ip addresses: %w", device.Name, err)
	}

	// move interface to pod network namespace
	nsPath := podNetworkNamespacePath(podSandbox)
	podNs, err := netns.OpenPinned(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
	}
	defer podNs.Close()

	if err := netlink.LinkSetNsFd(link, podNs.FD()); err != nil {
		return fmt.Errorf("failed to move dummy device %s to pod %s network namespace: %w",
			device.Name, podSandbox.Name, err)
	}

	// re-assign addresses to interface
	if err := podNs.Do(func() error {
		for _, addr := range addrs {
			if err := netlink.AddrAdd(link, &addr); err != nil {
				return fmt.Errorf("failed to add addr %s to device %s: %w", addr.String(), link.Attrs().Name, err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to add addresses to device %s: %w", link.Attrs().Name, err)
	}

	driver.logger.DebugContext(ctx, "Device moved to pod netns",
		logfields.Device, device.Name,
		logfields.K8sNamespace, podSandbox.Namespace,
		logfields.Name, podSandbox.Name,
		logfields.IPAddrs, addrs,
	)

	return nil
}

func (driver *Driver) StopContainer(ctx context.Context, podSandbox *api.PodSandbox, container *api.Container) ([]*api.ContainerUpdate, error) {
	nsPath := podNetworkNamespacePath(podSandbox)
	podNs, err := netns.OpenPinned(nsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
	}
	defer podNs.Close()

	hostNsPath := "/proc/1/ns/net"
	hostNs, err := netns.OpenPinned(hostNsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open pinned netns at %s: %w", hostNsPath, err)
	}
	defer hostNs.Close()

	podUID := types.UID(podSandbox.Uid)
	driver.lock.Lock()
	allocatedDevices := driver.podDeviceConfig[podUID]
	driver.lock.Unlock()

	deviceAddrs := make(map[netlink.Link][]netlink.Addr)

	if err := podNs.Do(func() error {
		links, err := safenetlink.LinkList()
		if err != nil {
			return fmt.Errorf("failed to get links: %w", err)
		}
		for _, link := range links {
			for _, device := range allocatedDevices {
				if device.Name != link.Attrs().Name {
					continue
				}

				// fetch interface IP addresses
				addrs, err := safenetlink.AddrList(link, netlink.FAMILY_ALL)
				if err != nil {
					return fmt.Errorf("failed to get dummy device %s ip addresses: %w", device.Name, err)
				}
				deviceAddrs[link] = addrs

				// move interface back to host network namespace
				if err := netlink.LinkSetNsFd(link, hostNs.FD()); err != nil {
					return fmt.Errorf("failed to move dummy device %s from pod %s to host network namespace: %w", device.Name, podSandbox.Name, err)
				}

				driver.logger.DebugContext(ctx, "Device %s has been moved back to host netns",
					logfields.Device, device.Name,
					logfields.IPAddrs, addrs)
			}
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to move devices back to host network namespace: %w", err)
	}

	// re-assign addresses to interfaces
	for link, addrs := range deviceAddrs {
		for _, addr := range addrs {
			if err := netlink.AddrAdd(link, &addr); err != nil {
				return nil, fmt.Errorf("failed to add addr %s to device %s: %w", addr.String(), link.Attrs().Name, err)
			}
		}
	}

	return nil, nil
}

func podNetworkNamespace(pod *api.PodSandbox) string {
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			return namespace.Path
		}
	}
	return ""
}

func podNetworkNamespacePath(pod *api.PodSandbox) string {
	return filepath.Join(defaults.NetNsPath, filepath.Base(podNetworkNamespace(pod)))
}
