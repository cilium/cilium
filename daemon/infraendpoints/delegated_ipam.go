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
	"github.com/cilium/cilium/pkg/node"
)

const (
	// delegatedIPAMContainerIDPrefix is prefixed to the local node name to form a
	// stable, per-node CNI container ID for ingress IP allocations.
	delegatedIPAMContainerIDPrefix = "cilium-ingress-"

	// delegatedIPAMIfName is the CNI_IFNAME used for ingress IP allocations, not a
	// real interface, but part of the IPAM bookkeeping key so must match ADD/DEL.
	delegatedIPAMIfName = "eth0"

	// delegatedIPAMNetNS is the CNI_NETNS used for ingress IP allocations, the host
	// netns is used and CNI_NETNS_OVERRIDE=1 bypasses plugin-side netns validation.
	delegatedIPAMNetNS = "/proc/1/ns/net"

	// delegatedIPAMPodNamespace is the K8S_POD_NAMESPACE CNI arg, set to kube-system
	// since the agent (a kube-system component) owns this allocation.
	delegatedIPAMPodNamespace = "kube-system"
)

// delegatedIPAMContainerID returns the CNI container ID for ingress IP allocations on the given node.
func delegatedIPAMContainerID(nodeName string) string {
	return delegatedIPAMContainerIDPrefix + nodeName
}

// delegatedIPAMHostNetnsArgs wraps cniinvoke.Args to override AsEnv (see method comment).
type delegatedIPAMHostNetnsArgs struct {
	cniinvoke.Args
}

// newDelegatedIPAMArgs builds the CNI args for an ingress-IP ADD/DEL. The same construction is used
// for both so the bookkeeping key (containerID + ifname) matches; drift would leak external IPAM IPs.
func newDelegatedIPAMArgs(command, containerID, cniBinPath string) *delegatedIPAMHostNetnsArgs {
	return &delegatedIPAMHostNetnsArgs{
		Args: cniinvoke.Args{
			Command:     command,
			ContainerID: containerID,
			NetNS:       delegatedIPAMNetNS,
			IfName:      delegatedIPAMIfName,
			Path:        cniBinPath,
			PluginArgs: [][2]string{
				// IgnoreUnknown lets strict IPAM plugins (e.g. host-local) tolerate the K8S_POD_* args.
				{"IgnoreUnknown", "true"},
				{"K8S_POD_NAME", containerID},
				{"K8S_POD_NAMESPACE", delegatedIPAMPodNamespace},
			},
		},
	}
}

// AsEnv extends the wrapped Args' env with CNI_NETNS_OVERRIDE=1, which is required
// because we invoke the IPAM plugin against the host netns rather than a real container.
func (a *delegatedIPAMHostNetnsArgs) AsEnv() []string {
	env := a.Args.AsEnv()
	env = append(env, "CNI_NETNS_OVERRIDE=1")
	return env
}

// newDefaultCNIExec returns a default CNI exec implementation that pipes plugin stderr to the
// agent's stderr so plugin diagnostics surface in agent logs.
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
func (r *infraIPAllocator) allocateIngressIPsWithDelegatedIPAMExec(ctx context.Context, exec cniinvoke.Exec) (retErr error) {
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
	args := newDelegatedIPAMArgs("ADD", containerID, cniBinPath)
	rawResult, err := cniinvoke.ExecPluginWithResult(ctx, pluginPath, pluginConf.Bytes, args, exec)
	if err != nil {
		return fmt.Errorf("failed to execute IPAM plugin %q for ingress IP allocation: %w", ipamType, err)
	}

	// From this point the plugin holds an external lease keyed on containerID.
	// If we return an error later, issue a compensating DEL so retries don't
	// collide with an orphaned lease.
	defer func() {
		if retErr == nil {
			return
		}
		delArgs := newDelegatedIPAMArgs("DEL", containerID, cniBinPath)
		if delErr := cniinvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, delArgs, exec); delErr != nil {
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
// Failures are logged and swallowed: cleanup is best-effort because we cannot block agent startup
// on a misbehaving external plugin.
func (r *infraIPAllocator) deallocateIngressIPsWithDelegatedIPAMExec(ctx context.Context, exec cniinvoke.Exec) {
	pluginConf, err := r.delegatedIPAMPluginConfig()
	if err != nil {
		r.logger.Warn("Cannot deallocate ingress IPs with delegated IPAM", logfields.Error, err)
		return
	}
	ipamType := pluginConf.Network.IPAM.Type

	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		r.logger.Warn("Cannot deallocate ingress IPs with delegated IPAM, failed to get local node",
			logfields.Error, err,
		)
		return
	}
	if localNode.Name == "" {
		r.logger.Warn("Cannot deallocate ingress IPs with delegated IPAM, local node name is empty")
		return
	}

	cniBinPath := r.cniConfigManager.GetDelegatedIPAMCNIBinPath()
	pluginPath, err := exec.FindInPath(ipamType, []string{cniBinPath})
	if err != nil {
		r.logger.Warn(fmt.Sprintf("Failed to find IPAM plugin %q in %q for deallocation", ipamType, cniBinPath),
			logfields.Error, err,
		)
		return
	}

	args := newDelegatedIPAMArgs("DEL", delegatedIPAMContainerID(localNode.Name), cniBinPath)
	if err := cniinvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, args, exec); err != nil {
		r.logger.Warn("Failed to deallocate ingress IPs with delegated IPAM", logfields.Error, err)
		return
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
}
