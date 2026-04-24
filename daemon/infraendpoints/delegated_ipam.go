// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"fmt"
	"os"

	"github.com/containernetworking/cni/libcni"
	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"

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

// delegatedIPAMHostNetnsArgs wraps cniInvoke.Args to add CNI_NETNS_OVERRIDE=1,
// required because we invoke the IPAM plugin against the host netns (no container).
type delegatedIPAMHostNetnsArgs struct {
	cniInvoke.Args
}

// newDelegatedIPAMArgs builds the CNI args for an ingress-IP ADD/DEL. The same construction is used
// for both so the bookkeeping key (containerID + ifname) matches; drift would leak external IPAM IPs.
func newDelegatedIPAMArgs(command, containerID, cniBinPath string) *delegatedIPAMHostNetnsArgs {
	return &delegatedIPAMHostNetnsArgs{
		Args: cniInvoke.Args{
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

func (a *delegatedIPAMHostNetnsArgs) AsEnv() []string {
	env := a.Args.AsEnv()
	env = append(env, "CNI_NETNS_OVERRIDE=1")
	return env
}

// newDefaultCNIExec returns a default CNI exec implementation.
func newDefaultCNIExec() cniInvoke.Exec {
	return &cniInvoke.DefaultExec{
		RawExec: &cniInvoke.RawExec{Stderr: os.Stderr},
	}
}

// getDelegatedIPAMPluginConfig returns the cilium-cni plugin block from --read-cni-conf, surfaced via
// NetConf.PluginConfig. Verbatim bytes preserve plugin-specific IPAM fields not modeled by NetConf.
func (r *infraIPAllocator) getDelegatedIPAMPluginConfig() (*libcni.PluginConfig, error) {
	netConf := r.cniConfigManager.GetCustomNetConf()
	if netConf == nil {
		return nil, fmt.Errorf("no CNI configuration available for delegated IPAM, ensure --read-cni-conf is set")
	}
	if netConf.PluginConfig == nil {
		return nil, fmt.Errorf("CNI configuration has no plugin config, cannot invoke delegated IPAM without preserving plugin-specific fields")
	}
	if netConf.PluginConfig.Network.IPAM.Type == "" {
		return nil, fmt.Errorf("CNI configuration does not specify an IPAM type")
	}
	return netConf.PluginConfig, nil
}

// allocateIngressIPsWithDelegatedIPAMExec allocates ingress IPs using an external CNI IPAM plugin.
func (r *infraIPAllocator) allocateIngressIPsWithDelegatedIPAMExec(ctx context.Context, exec cniInvoke.Exec) error {
	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node for delegated IPAM ingress allocation: %w", err)
	}
	if localNode.Name == "" {
		return fmt.Errorf("local node name is empty, cannot derive stable container ID for delegated IPAM ingress allocation")
	}

	pluginConf, err := r.getDelegatedIPAMPluginConfig()
	if err != nil {
		return err
	}
	ipamType := pluginConf.Network.IPAM.Type

	cniBinPath := r.cniConfigManager.GetDelegatedIPAMCNIBinPath()
	pluginPath, err := exec.FindInPath(ipamType, []string{cniBinPath})
	if err != nil {
		return fmt.Errorf("failed to find IPAM plugin %q in %s: %w", ipamType, cniBinPath, err)
	}

	args := newDelegatedIPAMArgs("ADD", delegatedIPAMContainerID(localNode.Name), cniBinPath)
	rawResult, err := cniInvoke.ExecPluginWithResult(ctx, pluginPath, pluginConf.Bytes, args, exec)
	if err != nil {
		return fmt.Errorf("failed to execute IPAM plugin %q for ingress IP allocation: %w", ipamType, err)
	}

	result, err := cniTypesV1.NewResultFromResult(rawResult)
	if err != nil {
		return fmt.Errorf("failed to convert IPAM result: %w", err)
	}

	if len(result.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned no IPs")
	}

	for _, ipConfig := range result.IPs {
		ip := ipConfig.Address.IP
		if ip.To4() != nil {
			r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv4IngressIP = ip })
			r.logger.Info("Allocated IPv4 Ingress address via delegated IPAM", logfields.IPAddr, ip)
		} else {
			r.localNodeStore.Update(func(n *node.LocalNode) { n.IPv6IngressIP = ip })
			r.logger.Info("Allocated IPv6 Ingress address via delegated IPAM", logfields.IPAddr, ip)
		}
	}

	return nil
}

// deallocateIngressIPsWithDelegatedIPAMExec releases ingress IPs via the external CNI IPAM plugin.
func (r *infraIPAllocator) deallocateIngressIPsWithDelegatedIPAMExec(ctx context.Context, exec cniInvoke.Exec) {
	pluginConf, err := r.getDelegatedIPAMPluginConfig()
	if err != nil {
		r.logger.Warn("Cannot deallocate ingress IPs with delegated IPAM", logfields.Error, err)
		return
	}
	ipamType := pluginConf.Network.IPAM.Type

	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		r.logger.Warn("Cannot deallocate ingress IPs with delegated IPAM: failed to get local node",
			logfields.Error, err,
		)
		return
	}
	if localNode.Name == "" {
		r.logger.Warn("Cannot deallocate ingress IPs with delegated IPAM: local node name is empty, cannot derive stable container ID")
		return
	}

	cniBinPath := r.cniConfigManager.GetDelegatedIPAMCNIBinPath()
	pluginPath, err := exec.FindInPath(ipamType, []string{cniBinPath})
	if err != nil {
		r.logger.Warn("Failed to find IPAM plugin for deallocation",
			logfields.Error, err,
			"ipamType", ipamType,
		)
		return
	}

	args := newDelegatedIPAMArgs("DEL", delegatedIPAMContainerID(localNode.Name), cniBinPath)
	if err := cniInvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, args, exec); err != nil {
		r.logger.Warn("Failed to deallocate ingress IPs with delegated IPAM", logfields.Error, err)
		return
	}

	// Only log/clear if there were IPs to release, otherwise the DEL is a no-op startup cleanup.
	hadIngressIP := localNode.IPv4IngressIP != nil || localNode.IPv6IngressIP != nil
	if !hadIngressIP {
		r.logger.Debug("No prior ingress IPs to release, delegated IPAM DEL completed as no-op")
		return
	}

	r.localNodeStore.Update(func(n *node.LocalNode) {
		n.IPv4IngressIP = nil
		n.IPv6IngressIP = nil
	})

	r.logger.Info("Deallocated ingress IPs via delegated IPAM",
		logfields.IPv4, localNode.IPv4IngressIP,
		logfields.IPv6, localNode.IPv6IngressIP,
	)
}
