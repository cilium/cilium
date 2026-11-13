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
	"github.com/spf13/afero"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/time"
)

type ipamAction string

const (
	addrAdd ipamAction = "add"
	addrDel ipamAction = "del"
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

	driver.jg.Add(job.OneShot("network-driver-nri-plugin-run", func(ctx context.Context, health cell.Health) error {
		driver.logger.InfoContext(ctx, "starting NRI plugin")
		for {
			if err := driver.nriPlugin.Run(ctx); err != nil {
				driver.logger.ErrorContext(
					ctx, "NRI plugin failed",
					logfields.Error, err,
					logfields.Name, driver.config.DriverName,
				)

				health.Degraded("Network Driver NRI plugin failed", err)
			} else {
				health.OK("Network Driver NRI plugin registration successful")
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
// on containerd < 2.1 even across an agent restart. This mirrors how allocation state is
// rebuilt from ResourceClaims on restart: node-local runtime state reconstructed from a
// durable source rather than persisted to disk. We request no container updates.
//
// A sandbox that started while the agent was down never reached RunPodSandbox, so
// RX queues are leased here as well. Leasing an already leased queue is a no-op.
func (driver *Driver) Synchronize(ctx context.Context, pods []*api.PodSandbox, _ []*api.Container) ([]*api.ContainerUpdate, error) {
	driver.withLockNoErr(func() {
		n := 0
		for _, pod := range pods {
			networkNamespace := driver.rememberNetworkNamespace(pod)
			if networkNamespace == "" {
				continue
			}
			n++

			podAllocations := driver.allocationsForPod(kube_types.UID(pod.Uid))
			nsPath := path.Join(podNetNSPath, path.Base(networkNamespace))
			if err := driver.bindRXQueues(nsPath, pod, podAllocations); err != nil {
				driver.logger.WarnContext(ctx, "NRI Synchronize: failed to lease RX queue",
					logfields.K8sNamespace, pod.GetNamespace(),
					logfields.K8sPodName, pod.GetName(),
					logfields.Error, err,
				)
			}
		}
		driver.logger.DebugContext(ctx, "NRI Synchronize: cached pod network namespaces",
			logfields.Count, n,
		)
	})
	return nil, nil
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

		// Task is alive here, so the netns is populated. Cache it keyed by sandbox ID so a
		// later StopPodSandbox can recover it on containerd < 2.1.
		networkNamespace := driver.rememberNetworkNamespace(podSandbox)
		// host network pods cannot allocate network devices
		// nothing for us here
		if networkNamespace == "" {
			log.DebugContext(ctx, "RunPodSandbox pod using host network cannot claim host devices")
			return nil
		}

		log = log.With(logfields.NetNamespace, networkNamespace)

		// Collect all allocations for this pod from the statedb table.
		podAllocations := driver.allocationsForPod(kube_types.UID(podSandbox.Uid))
		if len(podAllocations) == 0 {
			log.DebugContext(ctx, "no allocation found")
			return nil
		}

		nsPath := path.Join(podNetNSPath, path.Base(networkNamespace))

		// Lease RX queues before any container starts, so a workload can
		// register the leased queue as soon as it runs.
		if err := driver.bindRXQueues(nsPath, podSandbox, podAllocations); err != nil {
			return err
		}
		if !hasNRIManagedInterface(podAllocations) {
			return nil
		}

		podNs, err := netns.OpenPinned(nsPath)
		if err != nil {
			return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
		}

		defer podNs.Close()

		// Check for interface name collisions with existing interfaces in pod netns
		if err := podNs.Do(func() error {
			if err := validateInterfaceNames(podAllocations); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return fmt.Errorf("pod interface allocations is invalid: %w", err)
		}

		for i := range podAllocations {
			a := &podAllocations[i]
			if a.Manager == types.DeviceManagerTypeRXQueue {
				// The RX queue was leased to the existing interface created by CNI.
				continue
			}
			l, err := deviceLink(a.Device)
			if err != nil {
				// A node reboot removes the pod netns and any on-demand link moved
				// into it, while restore reconstructs the allocation from the
				// ResourceClaim without recreating the link. Re-create the missing
				// device when the replacement sandbox starts.
				//
				// An agent-only restart synchronizes the existing sandbox and does not
				// reach this path, so this cannot duplicate a healthy in-pod link.
				if !errors.As(err, &netlink.LinkNotFoundError{}) {
					return err
				}

				log.InfoContext(ctx, "allocated device link not found; re-creating on demand",
					logfields.Device, a.Device.KernelIfName())

				if err := driver.recoverAllocationDevice(a); err != nil {
					return err
				}

				l, err = deviceLink(a.Device)
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

				if err := driver.configureIPs(l, addrAdd, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
					return err
				}

				if err := netlink.LinkSetUp(l); err != nil {
					return err
				}

				if err := driver.configureSysctl(l, a.Config); err != nil {
					return fmt.Errorf("failed to configure sysctl for device %s: %w", l.Attrs().Name, err)
				}

				return nil
			}); err != nil {
				log.ErrorContext(ctx, "failed to configure device",
					logfields.Device, a.Device.IfName(),
					logfields.Error, err)
				return err
			}
		}

		return nil
	})

	return err
}

func (driver *Driver) recoverAllocationDevice(a *allocation) error {
	name := a.Device.KernelIfName()
	recovered, err := a.Device.Recover(a.deviceAllocation())
	if err != nil {
		return fmt.Errorf("failed to re-create device %s on demand: %w", name, err)
	}
	if recovered == nil {
		return fmt.Errorf("device %s returned no recovered device", name)
	}

	a.Device = recovered
	driver.updateAllocationDevice(*a)
	return nil
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
		defer delete(driver.podNetns, podSandbox.Id)

		networkNamespace := driver.getNetworkNamespace(podSandbox)
		// host network pods cannot allocate network devices because it impacts the host
		if networkNamespace == "" {
			log.DebugContext(ctx, "StopPodSandbox pod using host network cannot claim host devices")
			return nil
		}

		log = log.With(logfields.NetNamespace, networkNamespace)

		podAllocations := driver.allocationsForPod(kube_types.UID(podSandbox.Uid))
		if len(podAllocations) == 0 {
			log.DebugContext(ctx, "no allocation found")
			return nil
		}
		if !hasNRIManagedInterface(podAllocations) {
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

		if err := podNs.Do(func() error {
			for _, a := range podAllocations {
				if a.Manager == types.DeviceManagerTypeRXQueue {
					// CNI owns the Pod netkit and tears it down with the sandbox.
					continue
				}
				if a.Manager == types.DeviceManagerTypeDummy {
					// dummy device is an on-demand virtual device: the
					// netns delete that follows tears them down, so there is
					// nothing to move back to the root namespace.
					continue
				}

				l, err := podLink(a)
				if err != nil {
					return err
				}

				if err := driver.configureIPs(l, addrDel, a.Config.IPv4Addr, a.Config.IPv6Addr); err != nil {
					return err
				}

				if err := netlink.LinkSetDown(l); err != nil {
					return err
				}

				// Rename back to original kernel name before moving to root
				// namespace. Move it back even if this fails: the device is
				// found by other means than its name.
				if renamed, err := configureIfName(l, a.Device.KernelIfName()); err != nil {
					driver.logger.ErrorContext(
						ctx, "failed to restore interface name",
						logfields.Error, err,
					)
				} else {
					l = renamed
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

		return nil
	})

	return err
}

// linkFinder is implemented by devices whose netdev cannot be found by name,
// such as SR-IOV VFs: their name changes once they have been in a pod.
type linkFinder interface {
	// FindLink returns the device's netdev in the caller's network namespace.
	FindLink() (netlink.Link, error)
}

// deviceLink returns d's netdev in the caller's network namespace.
func deviceLink(d types.Device) (netlink.Link, error) {
	if f, ok := d.(linkFinder); ok {
		return f.FindLink()
	}
	return safenetlink.LinkByName(d.KernelIfName())
}

// podLink returns the allocation's netdev in the pod network namespace (the
// caller's): by its podIfName, which the driver set, or else as deviceLink
// finds it.
func podLink(a allocation) (netlink.Link, error) {
	if a.Config.PodIfName != "" {
		return safenetlink.LinkByName(a.Config.PodIfName)
	}
	return deviceLink(a.Device)
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
	if ns, ok := driver.podNetns[pod.Id]; ok {
		return ns
	}

	return ""
}

// rememberNetworkNamespace records a pod's netns path keyed by sandbox ID, if the PodSandbox
// carries one. Called from RunPodSandbox and Synchronize, where the sandbox task is
// alive and the namespaces are populated. The caller already holds driver.lock.
func (driver *Driver) rememberNetworkNamespace(pod *api.PodSandbox) string {
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			if pod.Id != "" {
				driver.podNetns[pod.Id] = namespace.Path
			}
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

// configureSysctl applies the device config's interface-scoped sysctl
// settings inside the current (pod) netns. Must run after the interface has
// its final pod-facing name. Per-netns sysctls are torn down with the
// namespace, so StopPodSandbox has no corresponding revert.
func (driver *Driver) configureSysctl(l netlink.Link, cfg types.DeviceConfig) error {
	settings := buildSysctlSettings(cfg, l.Attrs().Name)
	if len(settings) == 0 {
		return nil
	}
	return sysctl.NewDirectSysctl(afero.NewOsFs(), driver.hostProcPath).ApplySettings(settings)
}

type rxQueueEndpointLookup interface {
	LookupCNIAttachmentID(string) *endpoint.Endpoint
}

var (
	openPodNetNS           = netns.OpenPinned
	rxQueueBind            = (*rxqueue.RXQueueDevice).BindRXQueue
	rxQueueNamespaceCookie = func(ns *netns.NetNS) (cookie uint64, err error) {
		err = ns.Do(func() error {
			cookie, err = netns.GetNetNSCookie()
			return err
		})
		return
	}
)

// bindRXQueues leases each RX queue allocated to a Pod to its verified CNI
// interface in the Pod network namespace at nsPath.
func (driver *Driver) bindRXQueues(nsPath string, sandbox *api.PodSandbox, allocations []allocation) error {
	// Don't let IPAM release the Pod's IPs between finding its CNI attachment
	// and recording the queue binding. Otherwise, release could miss the
	// new binding and make the IPs available for reuse.
	driver.rxQueueBindLock.Lock()
	defer driver.rxQueueBindLock.Unlock()

	var podNs *netns.NetNS
	for _, a := range allocations {
		if a.Manager != types.DeviceManagerTypeRXQueue {
			continue
		}
		device, ok := a.Device.(*rxqueue.RXQueueDevice)
		if !ok {
			return fmt.Errorf("RX queue device %s does not support leasing", a.DeviceName)
		}
		if sandbox.Id == "" || driver.endpoints == nil {
			return errors.New("RX queue binding requires a runtime sandbox ID and CNI endpoint")
		}
		attachmentID := sandbox.Id + ":" + device.PodIfName
		ep := driver.endpoints.LookupCNIAttachmentID(attachmentID)
		if ep == nil || ep.GetK8sPodUID() != sandbox.Uid || !ep.IsAlive() {
			return fmt.Errorf("RX queue CNI attachment %s does not belong to this Pod sandbox", attachmentID)
		}
		if ep.DatapathConfiguration.ExternalIpam {
			return errors.New("RX queue binding requires Cilium-managed IPAM")
		}
		if podNs == nil {
			ns, err := openPodNetNS(nsPath)
			if err != nil {
				return fmt.Errorf("failed to open pinned netns at %s: %w", nsPath, err)
			}
			defer ns.Close()
			podNs = ns
		}
		cookie, err := rxQueueNamespaceCookie(podNs)
		if err != nil {
			return fmt.Errorf("failed to verify RX queue network namespace: %w", err)
		}
		if cookie == 0 || cookie != ep.GetEndpointNetNsCookie() {
			return fmt.Errorf("RX queue CNI attachment %s has a different network namespace", attachmentID)
		}
		var addresses []netip.Addr
		for _, ip := range []netip.Addr{ep.IPv4Address(), ep.IPv6Address()} {
			if ip.IsValid() {
				addresses = append(addresses, ip.Unmap())
			}
		}
		if len(addresses) == 0 {
			return fmt.Errorf("RX queue CNI attachment %s has no allocated addresses", attachmentID)
		}
		bound, err := rxQueueBind(device, podNs, attachmentID, addresses)
		if bound != nil {
			a.Device = bound
			driver.updateAllocationDevice(a)
		}
		if err != nil {
			return fmt.Errorf("failed to lease RX queue from device %s: %w", a.DeviceName, err)
		}
	}
	return nil
}

func hasNRIManagedInterface(allocations []allocation) bool {
	for _, allocation := range allocations {
		if allocation.Manager != types.DeviceManagerTypeRXQueue {
			return true
		}
	}
	return false
}

// validateInterfaceNames checks if a pod's set of allocated devices
// contain valid interface names, that dont collide with interfaces in the pod namespace.
func validateInterfaceNames(alloc []allocation) error {
	existingLinks, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list existing interfaces in pod netns: %w", err)
	}

	existingNames := make(map[string]bool)
	for _, link := range existingLinks {
		existingNames[link.Attrs().Name] = true
	}

	// Check if any of our planned renames would collide with existing interfaces
	for _, a := range alloc {
		if a.Manager == types.DeviceManagerTypeRXQueue {
			continue
		}
		if a.Config.PodIfName != "" && existingNames[a.Config.PodIfName] {
			return fmt.Errorf(
				"interface name collision: %q already exists in pod namespace (possibly from CNI)",
				a.Config.PodIfName)
		}
	}

	return nil
}

func (driver *Driver) configureIPs(l netlink.Link, action ipamAction, ipv4, ipv6 netip.Prefix) error {
	var (
		addrs []netlink.Addr
		errs  error
	)

	if ipv4.IsValid() {
		addrs = append(addrs, netlink.Addr{
			IPNet: netipx.PrefixIPNet(ipv4),
		})
	}
	if ipv6.IsValid() {
		addrs = append(addrs, netlink.Addr{
			IPNet: netipx.PrefixIPNet(ipv6),
		})
	}

	for _, addr := range addrs {
		switch action {
		case addrAdd:
			if err := netlink.AddrAdd(l, &addr); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to add addr %s to device %s: %w", addr.String(), l.Attrs().Name, err))
			}
		case addrDel:
			if err := netlink.AddrDel(l, &addr); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to delete addr %s to device %s: %w", addr.String(), l.Attrs().Name, err))
			}
		}
	}

	return errs
}
