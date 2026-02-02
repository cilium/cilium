// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
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
					if err := driver.configureIPs(l, addrAdd, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
						return err
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

					if err := driver.configureIPs(l, addrDel, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
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

func (driver *Driver) configureIPs(l netlink.Link, action ipamAction, ipv4, ipv6 netip.Prefix) error {
	var (
		addrs []netlink.Addr
		errs  []error
	)

	if driver.ipv4Enabled && ipv4.IsValid() {
		addrs = append(addrs, netlink.Addr{
			IPNet: netipx.PrefixIPNet(ipv4),
		})
	}
	if driver.ipv6Enabled && ipv6.IsValid() {
		addrs = append(addrs, netlink.Addr{
			IPNet: netipx.PrefixIPNet(ipv6),
		})
	}

	for _, addr := range addrs {
		switch action {
		case addrAdd:
			if err := netlink.AddrAdd(l, &addr); err != nil {
				errs = append(errs, fmt.Errorf("failed to add addr %s to device %s: %w", addr.String(), l.Attrs().Name, err))
			}
		case addrDel:
			if err := netlink.AddrDel(l, &addr); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete addr %s to device %s: %w", addr.String(), l.Attrs().Name, err))
			}
		}
	}

	return errors.Join(errs...)
}

func (driver *Driver) startNRI(ctx context.Context) error {
	// register the NRI plugin
	nriOptions := []stub.Option{
		stub.WithPluginName(driver.config.DriverName),
		stub.WithPluginIdx("00"),
		// https://github.com/containerd/nri/pull/173
		// Otherwise it silently exits the program
		stub.WithOnClose(func() {
			driver.logger.WarnContext(
				ctx, "NRI plugin closed",
				logfields.DriverName, driver.config.DriverName,
			)
		}),
	}

	nriStub, err := stub.New(driver, nriOptions...)
	if err != nil {
		return fmt.Errorf("failed to create plugin stub: %w", err)
	}

	driver.nriPlugin = nriStub

	driver.jg.Add(job.OneShot("networkdriver-nri-plugin-run", func(ctx context.Context, _ cell.Health) error {
		for {
			if err := driver.nriPlugin.Run(ctx); err != nil {
				driver.logger.ErrorContext(
					ctx, "NRI plugin failed",
					logfields.Error, err,
					logfields.Name, driver.config.DriverName,
				)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
				driver.logger.DebugContext(ctx, "Restarting NRI plugin", logfields.Name, driver.config.DriverName)
			}
		}
	}))

	return nil
}
