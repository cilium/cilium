// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/containernetworking/cni/libcni"
	cniinvoke "github.com/containernetworking/cni/pkg/invoke"
	cnicoretypes "github.com/containernetworking/cni/pkg/types"
	cnitypesv1 "github.com/containernetworking/cni/pkg/types/100"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
)

const (
	// delegatedIPAMOwnerIngress identifies ingress IP allocations.
	delegatedIPAMOwnerIngress = "ingress"

	// delegatedIPAMIfName is the CNI_IFNAME used for delegated IPAM allocations, not a
	// real interface, but part of the IPAM bookkeeping key so must match ADD/DEL.
	delegatedIPAMIfName = "eth0"

	// delegatedIPAMPodNamespace is the K8S_POD_NAMESPACE CNI arg, set to kube-system.
	delegatedIPAMPodNamespace = "kube-system"

	// CNI commands used for delegated IPAM.
	cniCommandAdd = "ADD"
	cniCommandDel = "DEL"
)

// delegatedIPAMContainerID returns a stable, per-node and per-owner CNI container ID.
func delegatedIPAMContainerID(owner, nodeName string) string {
	return "cilium-" + owner + "-" + nodeName
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

// slogWriter logs each non-empty line written to it at debug level.
type slogWriter struct {
	logger *slog.Logger
}

func (w slogWriter) Write(p []byte) (int, error) {
	for line := range bytes.Lines(p) {
		if l := bytes.TrimSpace(line); len(l) > 0 {
			w.logger.Debug("Delegated IPAM plugin stderr", logfields.Message, string(l))
		}
	}
	return len(p), nil
}

// newDefaultCNIExec returns a default CNI exec implementation that logs plugin stderr
// via logger. On plugin failure, stderr is part of the returned error instead.
func newDefaultCNIExec(logger *slog.Logger) cniinvoke.Exec {
	return &cniinvoke.DefaultExec{
		RawExec: &cniinvoke.RawExec{Stderr: slogWriter{logger: logger}},
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

// execDelegatedIPAM invokes the delegated IPAM plugin with the given CNI command for
// owner, from within an ephemeral network namespace. A result is only returned for
// ADD: per the CNI spec DEL produces no output, which ExecPluginWithResult would
// fail to parse.
func (r *infraIPAllocator) execDelegatedIPAM(ctx context.Context, command, owner string) (cnicoretypes.Result, error) {
	pluginConf, err := r.delegatedIPAMPluginConfig()
	if err != nil {
		return nil, err
	}
	ipamType := pluginConf.Network.IPAM.Type

	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get local node: %w", err)
	}

	cniBinPath := r.cniConfigManager.GetDelegatedIPAMCNIBinPath()
	pluginPath, err := r.cniExec.FindInPath(ipamType, []string{cniBinPath})
	if err != nil {
		return nil, fmt.Errorf("failed to find IPAM plugin %q in %q: %w", ipamType, cniBinPath, err)
	}

	netns, err := r.newNetNS()
	if err != nil {
		return nil, err
	}
	defer netns.Close()
	r.logger.Debug("Created ephemeral netns for delegated IPAM",
		logfields.NetNSName, netns.Path(),
		logfields.Owner, owner,
	)

	args := newDelegatedIPAMArgs(command, delegatedIPAMContainerID(owner, localNode.Name), cniBinPath, netns)

	var result cnicoretypes.Result
	switch command {
	case cniCommandAdd:
		result, err = cniinvoke.ExecPluginWithResult(ctx, pluginPath, pluginConf.Bytes, args, r.cniExec)
	case cniCommandDel:
		err = cniinvoke.ExecPluginWithoutResult(ctx, pluginPath, pluginConf.Bytes, args, r.cniExec)
	default:
		return nil, fmt.Errorf("unsupported delegated IPAM command %q", command)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to execute IPAM plugin %q %s for %s IPs: %w", ipamType, command, owner, err)
	}
	return result, nil
}

// allocateDelegatedIPs allocates one IP per enabled family for owner using the
// external CNI IPAM plugin. The lease is keyed on owner and the local node name,
// so repeated calls for the same owner return the same lease.
func (r *infraIPAllocator) allocateDelegatedIPs(ctx context.Context, owner string) (ipv4, ipv6 netip.Addr, retErr error) {
	rawResult, err := r.execDelegatedIPAM(ctx, cniCommandAdd, owner)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}

	// From this point the plugin holds an external lease keyed on containerID and ifname.
	// If we return an error later, make a DEL call so retries don't collide with an
	// orphaned lease.
	defer func() {
		if retErr == nil {
			return
		}
		if _, delErr := r.execDelegatedIPAM(ctx, cniCommandDel, owner); delErr != nil {
			r.logger.Warn("Failed to release lease via delegated IPAM after allocation error, lease may be orphaned",
				logfields.Error, delErr,
				logfields.Owner, owner,
			)
		}
	}()

	result, err := cnitypesv1.NewResultFromResult(rawResult)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("failed to convert IPAM result: %w", err)
	}

	if len(result.IPs) == 0 {
		return netip.Addr{}, netip.Addr{}, errors.New("IPAM plugin returned no IPs")
	}

	for _, ipConfig := range result.IPs {
		ip := iputil.AddrFromIP(ipConfig.Address.IP)
		if !ip.IsValid() {
			continue
		}
		if ip.Is4() {
			if r.daemonConfig.EnableIPv4 {
				if !ipv4.IsValid() {
					ipv4 = ip
				}
				continue
			}
			r.logger.Debug("Ignoring IPv4 address returned by delegated IPAM, IPv4 is disabled",
				logfields.IPAddr, ip,
				logfields.Owner, owner,
			)
			continue
		}

		if r.daemonConfig.EnableIPv6 {
			if !ipv6.IsValid() {
				ipv6 = ip
			}
			continue
		}
		r.logger.Debug("Ignoring IPv6 address returned by delegated IPAM, IPv6 is disabled",
			logfields.IPAddr, ip,
			logfields.Owner, owner,
		)
	}

	if r.daemonConfig.EnableIPv4 && !ipv4.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("delegated IPAM did not return an IPv4 %s address", owner)
	}
	if r.daemonConfig.EnableIPv6 && !ipv6.IsValid() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("delegated IPAM did not return an IPv6 %s address", owner)
	}

	return ipv4, ipv6, nil
}

// deallocateDelegatedIPs releases the lease held for owner by the external CNI IPAM plugin.
func (r *infraIPAllocator) deallocateDelegatedIPs(ctx context.Context, owner string) error {
	_, err := r.execDelegatedIPAM(ctx, cniCommandDel, owner)
	return err
}

// allocateIngressIPsWithDelegatedIPAM allocates ingress IPs using an external CNI IPAM plugin.
func (r *infraIPAllocator) allocateIngressIPsWithDelegatedIPAM(ctx context.Context) error {
	ipv4, ipv6, err := r.allocateDelegatedIPs(ctx, delegatedIPAMOwnerIngress)
	if err != nil {
		return err
	}

	r.localNodeStore.Update(func(n *node.LocalNode) {
		if ipv4.IsValid() {
			n.IPv4IngressIP = iputil.AddrFrom(ipv4)
			r.logger.Info("Allocated IPv4 ingress address via delegated IPAM", logfields.IPAddr, ipv4)
		}
		if ipv6.IsValid() {
			n.IPv6IngressIP = iputil.AddrFrom(ipv6)
			r.logger.Info("Allocated IPv6 ingress address via delegated IPAM", logfields.IPAddr, ipv6)
		}
	})

	return nil
}

// deallocateIngressIPsWithDelegatedIPAM releases ingress IPs via the external CNI IPAM plugin.
func (r *infraIPAllocator) deallocateIngressIPsWithDelegatedIPAM(ctx context.Context) error {
	if err := r.deallocateDelegatedIPs(ctx, delegatedIPAMOwnerIngress); err != nil {
		return err
	}

	r.localNodeStore.Update(func(n *node.LocalNode) {
		if n.IPv4IngressIP.IsValid() {
			r.logger.Info("Deallocated IPv4 ingress address via delegated IPAM", logfields.IPAddr, n.IPv4IngressIP)
			n.IPv4IngressIP = iputil.Addr{}
		}
		if n.IPv6IngressIP.IsValid() {
			r.logger.Info("Deallocated IPv6 ingress address via delegated IPAM", logfields.IPAddr, n.IPv6IngressIP)
			n.IPv6IngressIP = iputil.Addr{}
		}
	})

	return nil
}
