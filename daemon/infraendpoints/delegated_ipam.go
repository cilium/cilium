// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/libcni"
	cniinvoke "github.com/containernetworking/cni/pkg/invoke"
	cnitypesv1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
)

const (
	// delegatedIPAMContainerIDPrefix is prefixed to the local node name to form a
	// stable, per-node CNI container ID for ingress IP allocations.
	delegatedIPAMContainerIDPrefix = "cilium-ingress-"

	// delegatedIPAMIfName is the CNI_IFNAME used for ingress IP allocations, not a
	// real interface, but part of the IPAM bookkeeping key so must match ADD/DEL.
	delegatedIPAMIfName = "eth0"

	// delegatedIPAMPodNamespace is the K8S_POD_NAMESPACE CNI arg, set to kube-system.
	delegatedIPAMPodNamespace = "kube-system"
)

func delegatedIPAMContainerID(nodeName string) string {
	return delegatedIPAMContainerIDPrefix + nodeName
}

type delegatedIPAMNetNS interface {
	Path() string
	// Close releases the netns handle.
	Close() error
}

type realDelegatedIPAMNetNS struct {
	ns *netns.NetNS
}

// newDelegatedIPAMNetNS creates a fresh, empty network namespace. The returned handle is unpinned.
func newDelegatedIPAMNetNS() (delegatedIPAMNetNS, error) {
	ns, err := netns.New()
	if err != nil {
		return nil, fmt.Errorf("create delegated IPAM netns: %w", err)
	}
	return &realDelegatedIPAMNetNS{ns: ns}, nil
}

func (s *realDelegatedIPAMNetNS) Path() string { return fmt.Sprintf("/proc/self/fd/%d", s.ns.FD()) }
func (s *realDelegatedIPAMNetNS) Close() error { return s.ns.Close() }

func newDelegatedIPAMArgs(command, containerID, cniBinPath string, netns delegatedIPAMNetNS) *cniinvoke.Args {
	return &cniinvoke.Args{
		Command:     command,
		ContainerID: containerID,
		NetNS:       netns.Path(),
		IfName:      delegatedIPAMIfName,
		Path:        cniBinPath,
		PluginArgs: [][2]string{
			{"IgnoreUnknown", "true"},
			{"K8S_POD_NAME", containerID},
			{"K8S_POD_NAMESPACE", delegatedIPAMPodNamespace},
		},
	}
}

// newDefaultCNIExec returns a default CNI exec implementation that pipes plugin stderr
// to the agent's stderr.
func newDefaultCNIExec() cniinvoke.Exec {
	return &cniinvoke.DefaultExec{
		RawExec: &cniinvoke.RawExec{Stderr: os.Stderr},
	}
}

// delegatedIPAMPluginConfig returns the cilium-cni plugin block from --read-cni-conf, surfaced via
// NetConf.PluginConfig. Verbatim bytes preserve plugin-specific IPAM fields not modeled by NetConf.
func (r *infraIPAllocator) delegatedIPAMPluginConfig() (*libcni.PluginConfig, error) {
	netConf := r.cniConfigManager.GetCustomNetConf()
	if netConf == nil {
		return nil, errors.New("no CNI configuration available for delegated IPAM, ensure --read-cni-conf is set")
	}
	if netConf.PluginConfig == nil {
		return nil, errors.New("CNI configuration has no plugin config, cannot invoke delegated IPAM without preserving plugin-specific fields")
	}
	if netConf.PluginConfig.Network == nil {
		return nil, errors.New("CNI plugin config has no parsed network section, cannot determine IPAM type for delegated IPAM")
	}
	if len(netConf.PluginConfig.Bytes) == 0 {
		return nil, errors.New("CNI plugin config has no preserved raw bytes, cannot invoke delegated IPAM without plugin-specific fields")
	}
	if netConf.PluginConfig.Network.IPAM.Type == "" {
		return nil, errors.New("CNI configuration does not specify an IPAM type")
	}
	return netConf.PluginConfig, nil
}

// allocateIngressIPsWithDelegatedIPAMExec allocates ingress IPs using an external CNI IPAM plugin.
func (r *infraIPAllocator) allocateIngressIPsWithDelegatedIPAMExec(ctx context.Context, exec cniinvoke.Exec) error {
	netns, err := newDelegatedIPAMNetNS()
	if err != nil {
		return err
	}
	return r.allocateIngressIPsWithDelegatedIPAMExecAndNetNS(ctx, exec, netns)
}

func (r *infraIPAllocator) allocateIngressIPsWithDelegatedIPAMExecAndNetNS(ctx context.Context, exec cniinvoke.Exec, netns delegatedIPAMNetNS) (retErr error) {
	defer netns.Close()
	r.logger.Debug("Created ephemeral netns for delegated IPAM ingress allocation", logfields.NetNSName, netns.Path())

	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node for delegated IPAM ingress allocation: %w", err)
	}
	if localNode.Name == "" {
		return errors.New("local node name is empty, cannot derive stable container ID for delegated IPAM ingress allocation")
	}

	pluginConf, err := r.delegatedIPAMPluginConfig()
	if err != nil {
		return err
	}
	ipamType := pluginConf.Network.IPAM.Type

	cniBinPath := r.cniConfigManager.GetDelegatedIPAMCNIBinPath()
	pluginPath, err := exec.FindInPath(ipamType, []string{cniBinPath})
	if err != nil {
		return fmt.Errorf("failed to find IPAM plugin %q in %q: %w", ipamType, cniBinPath, err)
	}

	containerID := delegatedIPAMContainerID(localNode.Name)
	args := newDelegatedIPAMArgs("ADD", containerID, cniBinPath, netns)

	rawResult, err := cniinvoke.ExecPluginWithResult(ctx, pluginPath, pluginConf.Bytes, args, exec)
	if err != nil {
		return fmt.Errorf("failed to execute IPAM plugin %q for ingress IP allocation: %w", ipamType, err)
	}

	// From this point the plugin holds an external lease keyed on containerID and ifname.
	// If we return an error later, make a DEL call so retries don't collide with an
	// orphaned lease.
	defer func() {
		if retErr == nil {
			return
		}
		args.Command = "DEL"
		if delErr := cniinvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, args, exec); delErr != nil {
			r.logger.Warn("Failed to release lease via delegated IPAM after allocation error, lease may be orphaned",
				logfields.Error, delErr,
			)
		}
	}()

	result, err := cnitypesv1.NewResultFromResult(rawResult)
	if err != nil {
		return fmt.Errorf("failed to convert IPAM result: %w", err)
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned no IPs")
	}

	var ipv4, ipv6 net.IP
	for _, ipConfig := range result.IPs {
		ip := ipConfig.Address.IP
		if ip.To4() != nil {
			if r.daemonConfig.EnableIPv4 {
				if ipv4 == nil {
					ipv4 = ip
				}
				continue
			}
			r.logger.Debug("Ignoring IPv4 ingress IP returned by delegated IPAM, IPv4 is disabled",
				logfields.IPAddr, ip,
			)
			continue
		}

		if r.daemonConfig.EnableIPv6 {
			if ipv6 == nil {
				ipv6 = ip
			}
			continue
		}
		r.logger.Debug("Ignoring IPv6 ingress IP returned by delegated IPAM, IPv6 is disabled",
			logfields.IPAddr, ip,
		)
	}

	if r.daemonConfig.EnableIPv4 && ipv4 == nil {
		return fmt.Errorf("delegated IPAM plugin %q did not return an IPv4 ingress address", ipamType)
	}
	if r.daemonConfig.EnableIPv6 && ipv6 == nil {
		return fmt.Errorf("delegated IPAM plugin %q did not return an IPv6 ingress address", ipamType)
	}

	r.localNodeStore.Update(func(n *node.LocalNode) {
		if ipv4 != nil {
			n.IPv4IngressIP = ipv4
			r.logger.Info("Allocated IPv4 ingress address via delegated IPAM", logfields.IPAddr, ipv4)
		}
		if ipv6 != nil {
			n.IPv6IngressIP = ipv6
			r.logger.Info("Allocated IPv6 ingress address via delegated IPAM", logfields.IPAddr, ipv6)
		}
	})

	return nil
}

// deallocateIngressIPsWithDelegatedIPAMExec releases ingress IPs via the external CNI IPAM plugin.
func (r *infraIPAllocator) deallocateIngressIPsWithDelegatedIPAMExec(ctx context.Context, exec cniinvoke.Exec) error {
	netns, err := newDelegatedIPAMNetNS()
	if err != nil {
		return fmt.Errorf("netns unavailable: %w", err)
	}
	return r.deallocateIngressIPsWithDelegatedIPAMExecAndNetNS(ctx, exec, netns)
}

func (r *infraIPAllocator) deallocateIngressIPsWithDelegatedIPAMExecAndNetNS(ctx context.Context, exec cniinvoke.Exec, netns delegatedIPAMNetNS) error {
	defer netns.Close()
	r.logger.Debug("Created ephemeral netns for delegated IPAM ingress deallocation", logfields.NetNSName, netns.Path())

	pluginConf, err := r.delegatedIPAMPluginConfig()
	if err != nil {
		return err
	}
	ipamType := pluginConf.Network.IPAM.Type

	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}
	if localNode.Name == "" {
		return errors.New("local node name is empty")
	}

	cniBinPath := r.cniConfigManager.GetDelegatedIPAMCNIBinPath()
	pluginPath, err := exec.FindInPath(ipamType, []string{cniBinPath})
	if err != nil {
		return fmt.Errorf("failed to find IPAM plugin %q in %q: %w", ipamType, cniBinPath, err)
	}

	args := newDelegatedIPAMArgs("DEL", delegatedIPAMContainerID(localNode.Name), cniBinPath, netns)

	if err := cniinvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, args, exec); err != nil {
		return fmt.Errorf("failed to execute IPAM plugin %q for ingress IP deallocation: %w", ipamType, err)
	}

	r.localNodeStore.Update(func(n *node.LocalNode) {
		n.IPv4IngressIP = nil
		n.IPv6IngressIP = nil
	})

	if localNode.IPv4IngressIP != nil {
		r.logger.Info("Deallocated IPv4 ingress address via delegated IPAM", logfields.IPAddr, localNode.IPv4IngressIP)
	}
	if localNode.IPv6IngressIP != nil {
		r.logger.Info("Deallocated IPv6 ingress address via delegated IPAM", logfields.IPAddr, localNode.IPv6IngressIP)
	}
	return nil
}
