// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/vishvananda/netlink"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// Overridden by privileged tests to keep namespace moves isolated.
	podNetNSPath  = defaults.NetNsPath
	rootNetNSPath = "/proc/1/ns/net"
)

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

// Synchronize is invoked by the runtime when the NRI plugin (re)connects — notably right
// after an agent restart — with every running pod. The sandbox tasks are alive here, so
// the netns is populated; we capture it so a later StopPodSandbox can recover the netns
// on containerd < 2.1 even across an agent restart. This mirrors how driver.allocations
// is rebuilt from ResourceClaims on restart: node-local runtime state reconstructed from
// a durable source rather than persisted to disk. We request no container updates.
func (driver *Driver) Synchronize(ctx context.Context, pods []*api.PodSandbox, _ []*api.Container) ([]*api.ContainerUpdate, error) {
	err := driver.withLock(func() error {
		n := 0
		for _, pod := range pods {
			if driver.rememberNetworkNamespace(pod) != "" {
				n++
			}
		}
		driver.logger.DebugContext(ctx, "NRI Synchronize: cached pod network namespaces",
			logfields.Count, n,
		)
		return nil
	})

	return nil, err
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

		// Task is alive here, so the netns is populated. Cache it keyed by UID so a
		// later StopPodSandbox can recover it on containerd < 2.1.
		networkNamespace := driver.rememberNetworkNamespace(podSandbox)
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

		nsPath := path.Join(podNetNSPath, path.Base(networkNamespace))

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
					// The kernel link can be absent here when the node
					// rebooted: the reboot reaped the pod netns (and with
					// it any on-demand device such as a dummy
					// device), and the restore path rebuilt the
					// in-memory allocation WITHOUT re-creating the kernel
					// device — Device.Setup runs only on the prepare path,
					// which is short-circuited for a restored allocation.
					//
					// Only the (re)creation of the sandbox drives
					// RunPodSandbox, so this is the one moment that
					// unambiguously means "the device must exist now but
					// doesn't". An agent restart leaves the sandbox intact
					// and never reaches here, so re-creating on demand
					// cannot duplicate a healthy in-pod link. Every
					// Device.Setup is idempotent (dummy adopts/recreates
					// via EEXIST, sr-iov re-applies VLAN, dummy is a no-op),
					// so this is safe to retry.
					if !errors.As(err, &netlink.LinkNotFoundError{}) {
						return err
					}

					log.InfoContext(ctx, "allocated device link not found; re-creating on demand",
						logfields.Device, a.Device.KernelIfName())

					if setupErr := a.Device.Setup(a.Config); setupErr != nil {
						return fmt.Errorf("failed to re-create device %s on demand: %w", a.Device.KernelIfName(), setupErr)
					}

					l, err = safenetlink.LinkByName(a.Device.KernelIfName())
					if err != nil {
						return fmt.Errorf("device %s still not found after re-creating it on demand: %w", a.Device.KernelIfName(), err)
					}
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

		// On containerd < 2.1 the stop event carries no namespaces; fall back to the
		// path cached at RunPodSandbox / Synchronize. Evict the cache entry on the way
		// out: this is the pod's terminal event, so the entry is no longer needed.
		defer delete(driver.podNetns, kube_types.UID(podSandbox.Uid))

		networkNamespace := driver.getNetworkNamespace(podSandbox)
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

		nsPath := path.Join(podNetNSPath, path.Base(networkNamespace))

		podNs, err := netns.OpenPinned(nsPath)
		if err != nil {
			return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
		}

		defer podNs.Close()

		// Get the root network namespace to move interfaces back to it
		rootNs, err := netns.OpenPinned(rootNetNSPath)
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

// getNetworkNamespace resolves the pod's network namespace path.
//
// On containerd >= 2.1 the NRI PodSandbox carries the OCI namespaces directly, so the
// first lookup succeeds for both RunPodSandbox and StopPodSandbox. On containerd < 2.1
// the StopPodSandbox event carries no namespaces (the sandbox task is killed before the
// NRI hook runs, so the spec comes back empty); we fall back to the path cached at
// RunPodSandbox / Synchronize. The caller already holds driver.lock.
//
// An empty return means a genuine host-network pod (no network namespace at
// RunPodSandbox either, so nothing was cached), which must be skipped.
func (driver *Driver) getNetworkNamespace(pod *api.PodSandbox) string {
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			return namespace.Path
		}
	}

	// containerd < 2.1 fallback: reuse the path captured while the task was alive.
	if ns, ok := driver.podNetns[kube_types.UID(pod.Uid)]; ok {
		return ns
	}

	return ""
}

// rememberNetworkNamespace records a pod's netns path keyed by UID, if the PodSandbox
// carries one. Called from RunPodSandbox and Synchronize, where the sandbox task is
// alive and the namespaces are populated. The caller already holds driver.lock.
func (driver *Driver) rememberNetworkNamespace(pod *api.PodSandbox) string {
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			driver.podNetns[kube_types.UID(pod.Uid)] = namespace.Path
			return namespace.Path
		}
	}
	return ""
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
