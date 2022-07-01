// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package launch

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/health/probe"
	"github.com/cilium/cilium/pkg/identity/cache"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/launcher"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/sysctl"
)

const (
	ciliumHealth = "cilium-health"
	netNSName    = "cilium-health"
	binaryName   = "cilium-health-responder"

	// vethName is the host-side veth link device name for cilium-health EP
	// (veth mode only).
	vethName = "lxc_health"

	// legacyVethName is the host-side cilium-health EP device name used in
	// older Cilium versions. Used for removal only.
	legacyVethName = "cilium_health"

	// epIfaceName is the endpoint-side link device name for cilium-health.
	epIfaceName = "cilium"

	// PidfilePath
	PidfilePath = "health-endpoint.pid"

	// LaunchTime is the expected time within which the health endpoint
	// should be able to be successfully run and its BPF program attached.
	LaunchTime = 30 * time.Second
)

func configureHealthRouting(netns, dev string, addressing *models.NodeAddressing, mtuConfig mtu.Configuration) error {
	routes := []route.Route{}

	if option.Config.EnableIPv4 {
		v4Routes, err := connector.IPv4Routes(addressing, mtuConfig.GetRouteMTU())
		if err == nil {
			routes = append(routes, v4Routes...)
		} else {
			log.Debugf("Couldn't get IPv4 routes for health routing")
		}
	}

	if option.Config.EnableIPv6 {
		v6Routes, err := connector.IPv6Routes(addressing, mtuConfig.GetRouteMTU())
		if err != nil {
			return fmt.Errorf("Failed to get IPv6 routes")
		}
		routes = append(routes, v6Routes...)
	}

	prog := "ip"
	args := []string{"netns", "exec", netns, "bash", "-c"}
	routeCmds := []string{}
	for _, rt := range routes {
		cmd := strings.Join(rt.ToIPCommand(dev), " ")
		log.WithField("netns", netns).WithField("command", cmd).Debug("Adding route")
		routeCmds = append(routeCmds, cmd)
	}
	cmd := strings.Join(routeCmds, " && ")
	args = append(args, cmd)

	log.Debugf("Running \"%s %+v\"", prog, args)
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err == nil && len(out) > 0 {
		log.Warn(out)
	}

	return err
}

func configureHealthInterface(netNS ns.NetNS, ifName string, ip4Addr, ip6Addr *net.IPNet) error {
	return netNS.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return err
		}

		if ip6Addr == nil {
			name := fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", ifName)
			// Ignore the error; if IPv6 is completely disabled
			// then it's okay if we can't write the sysctl.
			_ = sysctl.Write(name, "1")
		} else {
			if err = netlink.AddrAdd(link, &netlink.Addr{IPNet: ip6Addr}); err != nil {
				return err
			}
		}

		if ip4Addr != nil {
			if err = netlink.AddrAdd(link, &netlink.Addr{IPNet: ip4Addr}); err != nil {
				return err
			}
		}

		if err = netlink.LinkSetUp(link); err != nil {
			return err
		}

		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}

		if err = netlink.LinkSetUp(lo); err != nil {
			return err
		}

		return nil
	})
}

// Client wraps a client to a specific cilium-health endpoint instance, to
// provide convenience methods such as PingEndpoint().
type Client struct {
	host string
}

// PingEndpoint attempts to make an API ping request to the local cilium-health
// endpoint, and returns whether this was successful.
func (c *Client) PingEndpoint() error {
	return probe.GetHello(c.host)
}

// KillEndpoint attempts to kill any existing cilium-health endpoint if it
// exists.
//
// This is intended to be invoked in multiple situations:
// * The health endpoint has never been run before
// * The health endpoint was run during a previous run of the Cilium agent
// * The health endpoint crashed during the current run of the Cilium agent
//   and needs to be cleaned up before it is restarted.
func KillEndpoint() {
	path := filepath.Join(option.Config.StateDir, PidfilePath)
	scopedLog := log.WithField(logfields.PIDFile, path)
	scopedLog.Debug("Killing old health endpoint process")
	pid, err := pidfile.Kill(path)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed to kill cilium-health-responder")
	} else if pid != 0 {
		scopedLog.WithField(logfields.PID, pid).Debug("Killed endpoint process")
	}
}

// CleanupEndpoint cleans up remaining resources associated with the health
// endpoint.
//
// This is expected to be called after the process is killed and the endpoint
// is removed from the endpointmanager.
func CleanupEndpoint() {
	// Removes the interfaces used for the endpoint process, followed by the
	// deletion of the health namespace itself. The removal of the interfaces
	// is needed, because network namespace removal does not always trigger the
	// deletion of associated interfaces immediately (e.g. when a process in the
	// namespace marked for deletion has not yet been terminated).
	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeVeth:
		for _, iface := range []string{legacyVethName, vethName} {
			scopedLog := log.WithField(logfields.Veth, iface)
			if link, err := netlink.LinkByName(iface); err == nil {
				err = netlink.LinkDel(link)
				if err != nil {
					scopedLog.WithError(err).Info("Couldn't delete cilium-health veth device")
				}
			} else {
				scopedLog.WithError(err).Debug("Didn't find existing device")
			}
		}
	case datapathOption.DatapathModeIpvlan:
		if err := netns.RemoveIfFromNetNSWithNameIfBothExist(netNSName, epIfaceName); err != nil {
			log.WithError(err).WithField(logfields.Ipvlan, epIfaceName).
				Info("Couldn't delete cilium-health ipvlan slave device")
		}
	}

	if err := netns.RemoveNetNSWithName(netNSName); err != nil {
		log.WithError(err).Debug("Unable to remove cilium-health namespace")
	}
}

// EndpointAdder is any type which adds an endpoint to be managed by Cilium.
type EndpointAdder interface {
	AddEndpoint(owner regeneration.Owner, ep *endpoint.Endpoint, reason string) error
}

// LaunchAsEndpoint launches the cilium-health agent in a nested network
// namespace and attaches it to Cilium the same way as any other endpoint, but
// with special reserved labels.
//
// CleanupEndpoint() must be called before calling LaunchAsEndpoint() to ensure
// cleanup of prior cilium-health endpoint instances.
func LaunchAsEndpoint(baseCtx context.Context,
	owner regeneration.Owner,
	policyGetter policyRepoGetter,
	ipcache *ipcache.IPCache,
	mtuConfig mtu.Configuration,
	epMgr EndpointAdder,
	proxy endpoint.EndpointProxy,
	allocator cache.IdentityAllocator,
	routingConfig routingConfigurer) (*Client, error) {

	var (
		cmd  = launcher.Launcher{}
		info = &models.EndpointChangeRequest{
			ContainerName: ciliumHealth,
			State:         models.EndpointStateWaitingForIdentity,
			Addressing:    &models.AddressPair{},
		}
		healthIP               net.IP
		ip4Address, ip6Address *net.IPNet
	)

	if healthIP = node.GetEndpointHealthIPv6(); healthIP != nil {
		info.Addressing.IPV6 = healthIP.String()
		ip6Address = &net.IPNet{IP: healthIP, Mask: defaults.ContainerIPv6Mask}
	}
	if healthIP = node.GetEndpointHealthIPv4(); healthIP != nil {
		info.Addressing.IPV4 = healthIP.String()
		ip4Address = &net.IPNet{IP: healthIP, Mask: defaults.ContainerIPv4Mask}
	}

	if option.Config.EnableEndpointRoutes {
		disabled := false
		dpConfig := &models.EndpointDatapathConfiguration{
			InstallEndpointRoute: true,
			RequireEgressProg:    true,
			RequireRouting:       &disabled,
		}
		info.DatapathConfiguration = dpConfig
	}

	netNS, err := netns.ReplaceNetNSWithName(netNSName)
	if err != nil {
		return nil, err
	}

	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeVeth:
		_, epLink, err := connector.SetupVethWithNames(vethName, epIfaceName, mtuConfig.GetDeviceMTU(), info)
		if err != nil {
			return nil, fmt.Errorf("Error while creating veth: %s", err)
		}

		if err = netlink.LinkSetNsFd(epLink, int(netNS.Fd())); err != nil {
			return nil, fmt.Errorf("failed to move device %q to health namespace: %s", epIfaceName, err)
		}

	case datapathOption.DatapathModeIpvlan:
		m, err := connector.CreateAndSetupIpvlanSlave("",
			epIfaceName, netNS, mtuConfig.GetDeviceMTU(),
			option.Config.Ipvlan.MasterDeviceIndex,
			option.Config.Ipvlan.OperationMode, info)
		if err != nil {
			if errDel := netns.RemoveNetNSWithName(netNSName); errDel != nil {
				log.WithError(errDel).WithField(logfields.NetNSName, netNSName).
					Warning("Unable to remove network namespace")
			}
			return nil, err
		}
		defer m.Close()
	}

	if err = configureHealthInterface(netNS, epIfaceName, ip4Address, ip6Address); err != nil {
		return nil, fmt.Errorf("failed configure health interface %q: %s", epIfaceName, err)
	}

	pidfile := filepath.Join(option.Config.StateDir, PidfilePath)
	prog := "ip"
	args := []string{"netns", "exec", netNSName, binaryName, "--listen", strconv.Itoa(option.Config.ClusterHealthPort), "--pidfile", pidfile}
	cmd.SetTarget(prog)
	cmd.SetArgs(args)
	log.Debugf("Spawning health endpoint with command %q %q", prog, args)
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	// Create the endpoint
	ep, err := endpoint.NewEndpointFromChangeModel(baseCtx, owner, policyGetter, ipcache, proxy, allocator, info)
	if err != nil {
		return nil, fmt.Errorf("Error while creating endpoint model: %s", err)
	}

	// Wait until the cilium-health endpoint is running before setting up routes
	deadline := time.Now().Add(1 * time.Minute)
	for {
		if _, err := os.Stat(pidfile); err == nil {
			log.WithField("pidfile", pidfile).Debug("cilium-health agent running")
			break
		} else if time.Now().After(deadline) {
			return nil, fmt.Errorf("Endpoint failed to run: %s", err)
		} else {
			time.Sleep(1 * time.Second)
		}
	}

	// Set up the endpoint routes.
	if err = configureHealthRouting(info.ContainerName, epIfaceName, node.GetNodeAddressing(), mtuConfig); err != nil {
		return nil, fmt.Errorf("Error while configuring routes: %s", err)
	}

	if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
		// ENI mode does not support IPv6.
		if err := routingConfig.Configure(
			healthIP,
			mtuConfig.GetDeviceMTU(),
			option.Config.EgressMultiHomeIPRuleCompat,
		); err != nil {

			return nil, fmt.Errorf("Error while configuring health endpoint rules and routes: %s", err)
		}
	}

	if err := epMgr.AddEndpoint(owner, ep, "Create cilium-health endpoint"); err != nil {
		return nil, fmt.Errorf("Error while adding endpoint: %s", err)
	}

	if err := ep.PinDatapathMap(); err != nil {
		return nil, err
	}

	// Give the endpoint a security identity
	ctx, cancel := context.WithTimeout(baseCtx, LaunchTime)
	defer cancel()
	ep.UpdateLabels(ctx, labels.LabelHealth, nil, true)

	// Initialize the health client to talk to this instance.
	client := &Client{host: "http://" + net.JoinHostPort(healthIP.String(), strconv.Itoa(option.Config.ClusterHealthPort))}
	metrics.SubprocessStart.WithLabelValues(ciliumHealth).Inc()

	return client, nil
}

type policyRepoGetter interface {
	GetPolicyRepository() *policy.Repository
}

type routingConfigurer interface {
	Configure(ip net.IP, mtu int, compat bool) error
}
