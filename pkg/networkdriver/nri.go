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

// movedIface tracks an interface that was successfully moved into the pod netns
// so it can be moved back on rollback.
type movedIface struct {
	kernelIfName string
	podIfName    string // non-empty after the interface was renamed inside the pod netns
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

		podUID := kube_types.UID(podSandbox.Uid)
		alloc, ok := driver.allocations[podUID]
		if !ok {
			l.DebugContext(ctx, "no allocation found")
			return nil
		}

		nsPath := path.Join(defaults.NetNsPath, path.Base(networkNamespace))

		podNs, err := netns.OpenPinned(nsPath)
		if err != nil {
			return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
		}
		defer podNs.Close()

		// Open root netns upfront — needed for rollback on partial failure.
		rootNs, err := netns.OpenPinned("/proc/1/ns/net")
		if err != nil {
			return fmt.Errorf("failed to open root netns: %w", err)
		}
		defer rootNs.Close()

		// Check for interface name collisions with existing interfaces in pod netns.
		if err := podNs.Do(func() error {
			return validateInterfaceNames(alloc)
		}); err != nil {
			return fmt.Errorf("pod interface allocations is invalid: %w", err)
		}

		// Track successfully-moved interfaces for rollback on partial failure.
		var moved []movedIface

		for _, devices := range alloc {
			for _, a := range devices {
				link, err := safenetlink.LinkByName(a.Device.KernelIfName())
				if err != nil {
					rollbackMovedInterfaces(moved, podNs, rootNs)
					return fmt.Errorf("failed to find interface %s: %w", a.Device.KernelIfName(), err)
				}

				if err := netlink.LinkSetNsFd(link, podNs.FD()); err != nil {
					rollbackMovedInterfaces(moved, podNs, rootNs)
					return fmt.Errorf("failed to move interface %s to pod netns: %w", a.Device.KernelIfName(), err)
				}

				entry := movedIface{kernelIfName: a.Device.KernelIfName()}

				configErr := podNs.Do(func() error {
					var e error
					link, e = configureInterfaceInNs(driver, link, a)
					if e != nil {
						return e
					}
					if a.Config.PodIfName != "" {
						entry.podIfName = a.Config.PodIfName
					}
					return nil
				})

				if configErr != nil {
					// The interface has been moved to the pod netns but configuration failed.
					// Add a partial entry so rollback can find and move it back.
					moved = append(moved, entry)
					rollbackMovedInterfaces(moved, podNs, rootNs)
					return fmt.Errorf("failed to configure device %s: %w", a.Device.KernelIfName(), configErr)
				}

				moved = append(moved, entry)
			}
		}

		// All interfaces configured successfully.
		// Persist the netns path in each claim's status (best-effort, async).
		allocSnapshot := snapshotAlloc(alloc)
		go driver.persistPodNetns(context.WithoutCancel(ctx), nsPath, podUID, allocSnapshot)

		return nil
	})

	return err
}

// rollbackMovedInterfaces moves all successfully-moved interfaces back to the
// root netns. Must be called when RunPodSandbox fails partway through.
func rollbackMovedInterfaces(moved []movedIface, podNs, rootNs *netns.NetNS) {
	podNs.Do(func() error { //nolint:errcheck
		for i := len(moved) - 1; i >= 0; i-- {
			m := moved[i]

			// Find the interface by its current name inside the pod netns.
			currentName := m.kernelIfName
			if m.podIfName != "" {
				currentName = m.podIfName
			}

			link, err := safenetlink.LinkByName(currentName)
			if err != nil {
				continue
			}

			// Rename back to kernel name before moving to root netns.
			if m.podIfName != "" {
				link, _ = configureIfName(link, m.kernelIfName)
			}

			netlink.LinkSetNsFd(link, rootNs.FD()) //nolint:errcheck
		}
		return nil
	})
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

		podUID := kube_types.UID(podSandbox.Uid)
		alloc, ok := driver.allocations[podUID]
		if !ok {
			l.DebugContext(ctx, "no allocation found")
			return nil
		}

		nsPath := path.Join(defaults.NetNsPath, path.Base(networkNamespace))

		if err := driver.moveInterfacesToRootNs(ctx, nsPath, alloc); err != nil {
			l.ErrorContext(ctx, "failed to move interfaces back to root netns", logfields.Error, err)
			return err
		}

		// Clear the PodNetns field in claim status (best-effort, async).
		allocSnapshot := snapshotAlloc(alloc)
		go driver.persistPodNetns(context.WithoutCancel(ctx), "", podUID, allocSnapshot)

		return nil
	})

	return err
}

// moveInterfacesToRootNs opens the pod netns at nsPath, deconfigures all interfaces
// in alloc, renames them back to their kernel name, and moves them to the root netns.
// Errors for individual interfaces are logged and skipped; the function always
// attempts to process all interfaces.
func (driver *Driver) moveInterfacesToRootNs(
	ctx context.Context,
	nsPath string,
	alloc map[kube_types.UID][]allocation,
) error {
	podNs, err := netns.OpenPinned(nsPath)
	if err != nil {
		return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
	}
	defer podNs.Close()

	rootNs, err := netns.OpenPinned("/proc/1/ns/net")
	if err != nil {
		return fmt.Errorf("failed to open root netns: %w", err)
	}
	defer rootNs.Close()

	return podNs.Do(func() error {
		for _, devices := range alloc {
			for _, a := range devices {
				if err := deconfigureAndMoveToRootNs(driver, a, rootNs.FD()); err != nil {
					driver.logger.ErrorContext(ctx, "failed to deconfigure/move interface to root netns",
						logfields.Device, a.Device.KernelIfName(),
						logfields.Error, err,
					)
					// continue with remaining interfaces
				}
			}
		}
		return nil
	})
}

// deconfigureAndMoveToRootNs removes IPs, brings down, renames an interface
// back to its kernel name, and moves it to the root netns.
// Must be called inside netns.Do() for the pod netns.
func deconfigureAndMoveToRootNs(driver *Driver, a allocation, rootNsFd int) error {
	// The interface may be named by PodIfName inside the pod netns.
	ifName := a.Device.KernelIfName()
	if a.Config.PodIfName != "" {
		ifName = a.Config.PodIfName
	}

	link, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifName, err)
	}

	if err := driver.configureIPs(link, addrDel, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
		// log and continue — we still want to move the interface back
		driver.logger.Warn("failed to remove IPs from interface, continuing",
			logfields.Interface, ifName, logfields.Error, err)
	}

	if err := netlink.LinkSetDown(link); err != nil {
		driver.logger.Warn("failed to bring down interface, continuing",
			logfields.Interface, ifName, logfields.Error, err)
	}

	// Rename back to kernel name before moving to root netns.
	if a.Config.PodIfName != "" {
		link, err = configureIfName(link, a.Device.KernelIfName())
		if err != nil {
			// Log but continue — try to move it back with whatever name it has.
			driver.logger.Warn("failed to rename interface back to kernel name, moving with current name",
				logfields.Interface, ifName, logfields.Error, err)
		}
	}

	if err := netlink.LinkSetNsFd(link, rootNsFd); err != nil {
		return fmt.Errorf("failed to move interface %s to root netns: %w", link.Attrs().Name, err)
	}

	return nil
}

// configureInterfaceInNs renames the interface (if PodIfName is set), assigns IPs,
// and brings the link up. Must be called inside netns.Do().
// Returns the (possibly refreshed) link.
func configureInterfaceInNs(driver *Driver, l netlink.Link, a allocation) (netlink.Link, error) {
	var err error

	// Rename interface to custom name if configured.
	if a.Config.PodIfName != "" {
		l, err = configureIfName(l, a.Config.PodIfName)
		if err != nil {
			return nil, fmt.Errorf("failed to set interface name: %w", err)
		}
	}

	if err := driver.configureIPs(l, addrAdd, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
		return nil, err
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return nil, err
	}

	return l, nil
}

// snapshotAlloc makes a shallow copy of the alloc map for use in goroutines
// that run after the lock is released.
func snapshotAlloc(alloc map[kube_types.UID][]allocation) map[kube_types.UID][]allocation {
	snap := make(map[kube_types.UID][]allocation, len(alloc))
	for k, v := range alloc {
		snap[k] = v
	}
	return snap
}

// persistPodNetns asynchronously updates the PodNetns field in every claim's
// device status for the given pod. Called after RunPodSandbox (nsPath set) and
// after StopPodSandbox (nsPath empty, to clear). Errors are logged, not propagated.
func (driver *Driver) persistPodNetns(
	ctx context.Context,
	nsPath string,
	podUID kube_types.UID,
	alloc map[kube_types.UID][]allocation,
) {
	claimsStore, err := driver.resourceClaims.Store(ctx)
	if err != nil {
		driver.logger.WarnContext(ctx, "persistPodNetns: failed to get claims store",
			logfields.PodUID, podUID,
			logfields.Error, err)
		return
	}

	for claimUID := range alloc {
		var found bool
		for _, claim := range claimsStore.List() {
			if claim.UID != claimUID {
				continue
			}
			found = true

			if err := driver.patchClaimPodNetns(ctx, claim, nsPath); err != nil {
				driver.logger.WarnContext(ctx, "persistPodNetns: failed to patch claim",
					logfields.UID, claimUID,
					logfields.PodUID, podUID,
					logfields.Error, err,
				)
			}
			break
		}

		if !found {
			driver.logger.WarnContext(ctx, "persistPodNetns: claim not found in store",
				logfields.UID, claimUID,
				logfields.PodUID, podUID,
			)
		}
	}
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
