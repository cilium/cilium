// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	kube_types "k8s.io/apimachinery/pkg/types"

	linuxRoute "github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/networkdriver/types"
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
		log := driver.logger.With(
			logfields.K8sNamespace, podSandbox.GetNamespace(),
			logfields.K8sPodName, podSandbox.GetName(),
			logfields.UID, podSandbox.GetUid(),
		)

		log.DebugContext(ctx, "RunPodSandbox request received")

		networkNamespace := getNetworkNamespace(podSandbox)
		// host network pods cannot allocate network devices
		// nothing for us here
		if networkNamespace == "" {
			log.DebugContext(ctx, "RunPodSandbox pod using host network cannot claim host devices")
			return nil
		}

		log = log.With(logfields.NetNamespace, networkNamespace)

		alloc, ok := driver.allocations[kube_types.UID(podSandbox.Uid)]
		if !ok {
			log.DebugContext(ctx, "no allocation found")
			// allocation not found/doesn't exist
			return nil
		}

		nsPath := path.Join(defaults.NetNsPath, path.Base(networkNamespace))

		podNs, err := netns.OpenPinned(nsPath)
		if err != nil {
			return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
		}

		defer podNs.Close()

		// Check for interface name collisions with existing interfaces in pod netns
		if err := podNs.Do(func() error {
			if err := validateInterfaceNames(alloc); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return fmt.Errorf("pod interface allocations is invalid: %w", err)
		}

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
					// Rename interface to custom name
					l, err = configureIfName(l, a.Config.PodIfName)
					if err != nil {
						return fmt.Errorf("failed to set interface name: %w", err)
					}

					if err := driver.configureIPs(l, add, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
						return err
					}
					if err := driver.configureRoutes(log, l, add, a.Config.Routes); err != nil {
						return err
					}
					if err := netlink.LinkSetUp(l); err != nil {
						return err
					}

					return nil
				}); err != nil {
					log.ErrorContext(ctx, "failed to configure device",
						logfields.Device, a.Device.IfName,
						logfields.Error, err)
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
		log := driver.logger.With(
			logfields.K8sNamespace, podSandbox.GetNamespace(),
			logfields.K8sPodName, podSandbox.GetName(),
			logfields.UID, podSandbox.GetUid(),
		)

		log.DebugContext(ctx, "StopPodSandbox request received")

		networkNamespace := getNetworkNamespace(podSandbox)
		// host network pods cannot allocate network devices because it impacts the host
		if networkNamespace == "" {
			log.DebugContext(ctx, "StopPodSandbox pod using host network cannot claim host devices")
			return nil
		}

		log = log.With(logfields.NetNamespace, networkNamespace)

		alloc, ok := driver.allocations[kube_types.UID(podSandbox.Uid)]
		if !ok {
			log.DebugContext(ctx, "no allocation found")
			// allocation not found/doesn't exist
			return nil
		}

		nsPath := path.Join(defaults.NetNsPath, path.Base(networkNamespace))

		podNs, err := netns.OpenPinned(nsPath)
		if err != nil {
			return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
		}

		defer podNs.Close()

		// Get the root network namespace to move interfaces back to it
		rootNs, err := netns.OpenPinned("/proc/1/ns/net")
		if err != nil {
			return fmt.Errorf("failed to open root netns: %w", err)
		}
		defer rootNs.Close()

		for _, devices := range alloc {
			if err := podNs.Do(func() error {
				for _, a := range devices {
					// Determine the interface name in the pod namespace
					ifName := a.Device.KernelIfName()
					if a.Config.PodIfName != "" {
						ifName = a.Config.PodIfName
					}

					l, err := safenetlink.LinkByName(ifName)
					if err != nil {
						return err
					}

					if err := driver.configureIPs(l, del, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
						return err
					}

					if err := driver.configureRoutes(log, l, del, a.Config.Routes); err != nil {
						return err
					}

					if err := netlink.LinkSetDown(l); err != nil {
						return err
					}

					// Rename back to original kernel name before moving to root namespace
					l, err = configureIfName(l, a.Device.KernelIfName())
					if err != nil {
						driver.logger.ErrorContext(
							ctx, "failed to restore interface name",
							logfields.Error, err,
						)

						// we want to continue here to clean up the remaining, even if this one failed
						continue
					}

					// Always try to move back to root netns
					if err := netlink.LinkSetNsFd(l, rootNs.FD()); err != nil {
						driver.logger.WarnContext(ctx, "Failed to move interface to root namespace",
							logfields.Error, err,
							logfields.Device, a.Device.KernelIfName())
						// Log but don't return - continue with other devices
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

func (driver *Driver) configureIPs(l netlink.Link, act action, ipv4, ipv6 netip.Prefix) error {
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
		switch act {
		case add:
			if err := netlink.AddrAdd(l, &addr); err != nil {
				errs = append(errs, fmt.Errorf("failed to add addr %s to device %s: %w", addr.String(), l.Attrs().Name, err))
			}
		case del:
			if err := netlink.AddrDel(l, &addr); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete addr %s to device %s: %w", addr.String(), l.Attrs().Name, err))
			}
		}
	}

	return errors.Join(errs...)
}

func (driver *Driver) configureRoutes(logger *slog.Logger, l netlink.Link, act action, routes []types.Route) error {
	var errs []error
	for _, r := range routes {
		nextHop := net.IP(r.Gateway.AsSlice())
		route := linuxRoute.Route{
			Prefix:  *netipx.PrefixIPNet(r.Destination),
			Nexthop: &nextHop,
			Device:  l.Attrs().Name,
			Table:   unix.RT_TABLE_MAIN,
			Proto:   unix.RTPROT_STATIC,
		}

		switch act {
		case add:
			if err := linuxRoute.Upsert(logger, route); err != nil {
				errs = append(errs, fmt.Errorf("failed to add static route [%s via %s dev %s]: %w", r.Destination, r.Gateway, l.Attrs().Name, err))
			}
		case del:
			if err := linuxRoute.Delete(route); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete static route [%s via %s dev %s]: %w", r.Destination, r.Gateway, l.Attrs().Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// configureIfName renames an interface to newIfName if the current link name differs from the
// newIfName and newIfName is not empty.
func configureIfName(l netlink.Link, newIfName string) (netlink.Link, error) {
	if newIfName == "" || l.Attrs().Name == newIfName {
		// no changes needed
		return l, nil
	}

	if err := netlink.LinkSetName(l, newIfName); err != nil {
		return nil, fmt.Errorf("failed to rename interface from %s to %s: %w", l.Attrs().Name, newIfName, err)
	}

	// Refresh link reference after rename
	l, err := safenetlink.LinkByName(newIfName)
	if err != nil {
		return nil, fmt.Errorf("failed to get link after rename: %w", err)
	}

	return l, nil
}

// validateInterfaceNames checks if a pod's set of allocated devices
// contain valid interface names, that dont collide with interfaces in the pod namespace.
func validateInterfaceNames(alloc map[kube_types.UID][]allocation) error {
	existingLinks, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list existing interfaces in pod netns: %w", err)
	}

	existingNames := make(map[string]bool)
	for _, link := range existingLinks {
		existingNames[link.Attrs().Name] = true
	}

	// Check if any of our planned renames would collide with existing interfaces
	for _, devices := range alloc {
		for _, a := range devices {
			if a.Config.PodIfName != "" && existingNames[a.Config.PodIfName] {
				return fmt.Errorf(
					"interface name collision: %q already exists in pod namespace (possibly from CNI)",
					a.Config.PodIfName)
			}
		}
	}

	return nil
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
