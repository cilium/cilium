// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	cniinvoke "github.com/containernetworking/cni/pkg/invoke"
	cnitypesv1 "github.com/containernetworking/cni/pkg/types/100"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// delegatedIPAMRouterContainerIDPrefix is prefixed to the local node name
	// to form the container ID of the router IP lease.
	delegatedIPAMRouterContainerIDPrefix = "cilium-router-"

	// delegatedIPAMRouterIfName is the CNI_IFNAME of the router IP lease.
	delegatedIPAMRouterIfName = "cilium_host"

	// delegatedIPAMRouterLeaseFile, in the state directory, holds the result
	// of the router IP lease.
	delegatedIPAMRouterLeaseFile = "delegated-ipam-router-lease.json"
)

func delegatedIPAMRouterContainerID(nodeName string) string {
	return delegatedIPAMRouterContainerIDPrefix + nodeName
}

// delegatedIPAMRouterLease is the result of the router IP lease, kept the way
// libcni caches the results of a container runtime: the CNI contract doesn't
// allow a second ADD for the same container ID and interface without a DEL in
// between, so a restarted agent reuses the lease instead of adding it again.
// The state directory doesn't survive a reboot, and neither do the router
// addresses on cilium_host.
type delegatedIPAMRouterLease struct {
	ContainerID string          `json:"containerID"`
	IfName      string          `json:"ifName"`
	Result      json.RawMessage `json:"result"`
}

// needsDelegatedRouterIPs reports whether the router IPs of the enabled
// families have to come from the delegated IPAM plugin, i.e. delegated IPAM is
// in use and no static router address was configured for that family.
func (r *infraIPAllocator) needsDelegatedRouterIPs() bool {
	if r.daemonConfig.IPAM != ipamOption.IPAMDelegatedPlugin {
		return false
	}
	return (r.daemonConfig.EnableIPv4 && r.daemonConfig.LocalRouterIPv4 == "") ||
		(r.daemonConfig.EnableIPv6 && r.daemonConfig.LocalRouterIPv6 == "")
}

// allocateRouterIPsWithDelegatedIPAMExec leases the router (cilium_host)
// addresses from the delegated IPAM plugin, the same way the CNI plugin leases
// pod addresses. The lease is never released by the agent: it lives as long
// as the node. A restarted agent reuses the lease of its previous run;
// otherwise it releases whatever the plugin still holds for the container ID
// (e.g. from before a reboot) and leases again.
func (r *infraIPAllocator) allocateRouterIPsWithDelegatedIPAMExec(ctx context.Context, exec cniinvoke.Exec) (net.IP, net.IP, error) {
	netns, err := newDelegatedIPAMNetNS()
	if err != nil {
		return nil, nil, err
	}
	return r.allocateRouterIPsWithDelegatedIPAMExecAndNetNS(ctx, exec, netns)
}

func (r *infraIPAllocator) allocateRouterIPsWithDelegatedIPAMExecAndNetNS(ctx context.Context, exec cniinvoke.Exec, netns delegatedIPAMNetNS) (_, _ net.IP, retErr error) {
	defer netns.Close()

	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get local node for delegated IPAM router allocation: %w", err)
	}
	if localNode.Name == "" {
		return nil, nil, errors.New("local node name is empty, cannot derive stable container ID for delegated IPAM router allocation")
	}
	containerID := delegatedIPAMRouterContainerID(localNode.Name)

	if result := r.restoreDelegatedIPAMRouterLease(containerID); result != nil {
		ipv4, ipv6 := routerIPsFromResult(result)
		if err := r.checkDelegatedRouterIPs(ipv4, ipv6); err == nil {
			r.logger.Info("Reusing router addresses leased via delegated IPAM",
				logfields.ContainerID, containerID,
				logfields.IPv4, ipv4,
				logfields.IPv6, ipv6,
			)
			return ipv4, ipv6, nil
		}
		r.logger.Info("Previous router IP lease doesn't cover the enabled IP families, leasing again",
			logfields.ContainerID, containerID,
		)
	}

	pluginConf, err := r.delegatedIPAMPluginConfig()
	if err != nil {
		return nil, nil, err
	}
	ipamType := pluginConf.Network.IPAM.Type

	cniBinPath := r.cniConfigManager.GetDelegatedIPAMCNIBinPath()
	pluginPath, err := exec.FindInPath(ipamType, []string{cniBinPath})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find IPAM plugin %q in %q: %w", ipamType, cniBinPath, err)
	}

	args := newDelegatedIPAMArgs("DEL", containerID, cniBinPath, netns)
	args.IfName = delegatedIPAMRouterIfName

	// Without a lease from this boot, the plugin may still hold one for the
	// container ID, e.g. in an on-disk store that survived a reboot. ADD it
	// again only after a DEL, which plugins must accept when there's nothing
	// to release.
	if err := cniinvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, args, exec); err != nil {
		r.logger.Warn("Failed to release a previous router IP lease via delegated IPAM",
			logfields.ContainerID, containerID,
			logfields.Error, err,
		)
	}

	args.Command = "ADD"
	rawResult, err := cniinvoke.ExecPluginWithResult(ctx, pluginPath, pluginConf.Bytes, args, exec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute IPAM plugin %q for router IP allocation: %w", ipamType, err)
	}

	// From this point the plugin holds a lease for the container ID: release
	// it if we fail, so that a retry doesn't collide with it.
	defer func() {
		if retErr == nil {
			return
		}
		args.Command = "DEL"
		if delErr := cniinvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, args, exec); delErr != nil {
			r.logger.Warn("Failed to release router IP lease via delegated IPAM after allocation error, lease may be orphaned",
				logfields.Error, delErr,
			)
		}
	}()

	result, err := cnitypesv1.NewResultFromResult(rawResult)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert IPAM result: %w", err)
	}
	ipv4, ipv6 := routerIPsFromResult(result)
	if err := r.checkDelegatedRouterIPs(ipv4, ipv6); err != nil {
		return nil, nil, fmt.Errorf("delegated IPAM plugin %q: %w", ipamType, err)
	}

	r.saveDelegatedIPAMRouterLease(containerID, result)

	r.logger.Info("Leased router addresses via delegated IPAM",
		logfields.ContainerID, containerID,
		logfields.IPv4, ipv4,
		logfields.IPv6, ipv6,
	)
	return ipv4, ipv6, nil
}

// routerIPsFromResult returns the first IPv4 and IPv6 addresses of result.
func routerIPsFromResult(result *cnitypesv1.Result) (ipv4, ipv6 net.IP) {
	for _, ipConfig := range result.IPs {
		ip := ipConfig.Address.IP
		if ip.To4() != nil {
			if ipv4 == nil {
				ipv4 = ip.To4()
			}
		} else if ipv6 == nil {
			ipv6 = ip
		}
	}
	return ipv4, ipv6
}

// checkDelegatedRouterIPs fails if a family that needs a leased router
// address has none.
func (r *infraIPAllocator) checkDelegatedRouterIPs(ipv4, ipv6 net.IP) error {
	if r.daemonConfig.EnableIPv4 && r.daemonConfig.LocalRouterIPv4 == "" && ipv4 == nil {
		return errors.New("no IPv4 router address")
	}
	if r.daemonConfig.EnableIPv6 && r.daemonConfig.LocalRouterIPv6 == "" && ipv6 == nil {
		return errors.New("no IPv6 router address")
	}
	return nil
}

func (r *infraIPAllocator) delegatedIPAMRouterLeasePath() string {
	if r.daemonConfig.StateDir == "" {
		return ""
	}
	return filepath.Join(r.daemonConfig.StateDir, delegatedIPAMRouterLeaseFile)
}

// restoreDelegatedIPAMRouterLease returns the result of the router IP lease
// of a previous run for containerID, if there is one.
func (r *infraIPAllocator) restoreDelegatedIPAMRouterLease(containerID string) *cnitypesv1.Result {
	path := r.delegatedIPAMRouterLeasePath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.logger.Warn("Failed to read the router IP lease", logfields.Path, path, logfields.Error, err)
		}
		return nil
	}
	var lease delegatedIPAMRouterLease
	if err := json.Unmarshal(data, &lease); err != nil {
		r.logger.Warn("Ignoring unreadable router IP lease", logfields.Path, path, logfields.Error, err)
		return nil
	}
	if lease.ContainerID != containerID || lease.IfName != delegatedIPAMRouterIfName {
		return nil
	}
	result, err := cnitypesv1.NewResult(lease.Result)
	if err != nil {
		r.logger.Warn("Ignoring unreadable router IP lease", logfields.Path, path, logfields.Error, err)
		return nil
	}
	converted, err := cnitypesv1.NewResultFromResult(result)
	if err != nil {
		r.logger.Warn("Ignoring unreadable router IP lease", logfields.Path, path, logfields.Error, err)
		return nil
	}
	return converted
}

// saveDelegatedIPAMRouterLease keeps the result of the router IP lease for
// the next run. Without it, the next run releases and leases again, which may
// change the router addresses.
func (r *infraIPAllocator) saveDelegatedIPAMRouterLease(containerID string, result *cnitypesv1.Result) {
	path := r.delegatedIPAMRouterLeasePath()
	if path == "" {
		return
	}
	err := func() error {
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		data, err := json.Marshal(delegatedIPAMRouterLease{
			ContainerID: containerID,
			IfName:      delegatedIPAMRouterIfName,
			Result:      raw,
		})
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}()
	if err != nil {
		r.logger.Warn("Failed to save the router IP lease, the next agent start leases again",
			logfields.Path, path, logfields.Error, err)
	}
}
