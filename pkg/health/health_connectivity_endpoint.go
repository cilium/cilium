// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/spf13/afero"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	"github.com/cilium/cilium/pkg/endpointmanager"
	healthDefaults "github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/health/probe"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/launcher"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/time"
)

const (
	ciliumHealth = "cilium-health"
	binaryName   = "cilium-health-responder"

	// healthName is the host-side virtual device name for cilium-health EP
	healthName = "lxc_health"

	// legacyHealthName is the host-side cilium-health EP device name used in
	// older Cilium versions. Used for removal only.
	legacyHealthName = "cilium_health"

	// epIfaceName is the endpoint-side link device name for cilium-health.
	epIfaceName = "cilium"

	// LaunchTime is the expected time within which the health endpoint
	// should be able to be successfully run and its BPF program attached.
	LaunchTime = 30 * time.Second
)

func (h *ciliumHealthManager) getHealthRoutes(addressing *models.NodeAddressing, mtuConfig mtu.MTU) ([]route.Route, error) {
	routes := []route.Route{}

	if option.Config.EnableIPv4 {
		v4Routes, err := connector.IPv4Routes(addressing, mtuConfig.GetRouteMTU())
		if err == nil {
			routes = append(routes, v4Routes...)
		} else {
			h.logger.Debug("Couldn't get IPv4 routes for health routing")
		}
	}

	if option.Config.EnableIPv6 {
		v6Routes, err := connector.IPv6Routes(addressing, mtuConfig.GetRouteMTU())
		if err != nil {
			return nil, fmt.Errorf("Failed to get IPv6 routes")
		}
		routes = append(routes, v6Routes...)
	}

	return routes, nil
}

// configureHealthRouting is meant to be run inside the health service netns
func (h *ciliumHealthManager) configureHealthRouting(routes []route.Route, dev string) error {
	for _, rt := range routes {
		cmd := rt.ToIPCommand(dev)
		if len(cmd) < 2 {
			return fmt.Errorf("ip command %s not expected len!", cmd)
		}
		prog := cmd[0]
		args := cmd[1:]
		h.logger.Debug(fmt.Sprintf("Running \"%s %+v\"", prog, args))
		out, err := exec.Command(prog, args...).CombinedOutput()
		if err == nil && len(out) > 0 {
			h.logger.Warn(string(out),
				logfields.Prog, prog,
				logfields.Args, args,
			)
		} else if err != nil {
			return fmt.Errorf("error running %q with args %q: %w", prog, args, err)
		}
	}
	return nil
}

// configureHealthInterface is meant to be run inside the health service netns
func (h *ciliumHealthManager) configureHealthInterface(ifName string, ip4Addr, ip6Addr *net.IPNet) error {
	link, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	if ip6Addr == nil {
		// Use the direct sysctl without reconciliation of errors since we're in a different
		// network namespace and thus can't use the normal sysctl API.
		sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), option.Config.ProcFs)
		// Ignore the error; if IPv6 is completely disabled
		// then it's okay if we can't write the sysctl.
		_ = sysctl.Enable([]string{"net", "ipv6", "conf", ifName, "disable_ipv6"})
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

	lo, err := safenetlink.LinkByName("lo")
	if err != nil {
		return err
	}

	if err = netlink.LinkSetUp(lo); err != nil {
		return err
	}

	return nil
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

// killEndpoint attempts to kill any existing cilium-health endpoint if it
// exists.
//
// This is intended to be invoked in multiple situations:
//   - The health endpoint has never been run before
//   - The health endpoint was run during a previous run of the Cilium agent
//   - The health endpoint crashed during the current run of the Cilium agent
//     and needs to be cleaned up before it is restarted.
func (h *ciliumHealthManager) killEndpoint() {
	path := filepath.Join(option.Config.StateDir, healthDefaults.PidfilePath)
	scopedLog := h.logger.With(logfields.PIDFile, path)
	scopedLog.Debug("Killing old health endpoint process")
	pid, err := pidfile.Kill(path)
	if err != nil {
		scopedLog.Warn("Failed to kill cilium-health-responder", logfields.Error, err)
	} else if pid != 0 {
		scopedLog.Debug("Killed endpoint process", logfields.PID, pid)
	}
}

// cleanupEndpoint cleans up remaining resources associated with the health
// endpoint.
//
// This is expected to be called after the process is killed and the endpoint
// is removed from the endpointmanager.
func (h *ciliumHealthManager) cleanupEndpoint() {
	// Removes the interfaces used for the endpoint process.
	//
	// Explicit removal is performed to ensure that everything referencing the network namespace
	// the endpoint process is executed under is disposed, so that the network namespace itself is properly disposed.
	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeVeth, datapathOption.DatapathModeNetkit, datapathOption.DatapathModeNetkitL2:
		for _, iface := range []string{legacyHealthName, healthName} {
			scopedLog := h.logger.With(logfields.Interface, iface)
			if link, err := safenetlink.LinkByName(iface); err == nil {
				err = netlink.LinkDel(link)
				if err != nil {
					scopedLog.Info("Couldn't delete cilium-health device",
						logfields.DatapathMode, option.Config.DatapathMode,
						logfields.Error, err,
					)
				}
			} else {
				scopedLog.Debug("Didn't find existing device", logfields.Error, err)
			}
		}
	}
}

// launchAsEndpoint launches the cilium-health agent in a nested network
// namespace and attaches it to Cilium the same way as any other endpoint, but
// with special reserved labels.
//
// cleanupEndpoint() must be called before calling launchAsEndpoint() to ensure
// cleanup of prior cilium-health endpoint instances.
func (h *ciliumHealthManager) launchAsEndpoint(baseCtx context.Context, endpointCreator endpointcreator.EndpointCreator, endpointManager endpointmanager.EndpointsModify, mtuConfig mtu.MTU, bigTCPConfig *bigtcp.Configuration, routingConfig routingConfigurer, sysctl sysctl.Sysctl) (*Client, error) {
	var (
		cmd  = launcher.Launcher{Logger: h.logger}
		info = &models.EndpointChangeRequest{
			ContainerName: ciliumHealth,
			State:         models.EndpointStateWaitingDashForDashIdentity.Pointer(),
			Addressing:    &models.AddressPair{},
		}
		healthIP               net.IP
		ip4Address, ip6Address *net.IPNet
	)

	if healthIPv6 := node.GetEndpointHealthIPv6(logging.DefaultSlogLogger); healthIPv6 != nil {
		info.Addressing.IPV6 = healthIPv6.String()
		info.Addressing.IPV6PoolName = ipam.PoolDefault().String()
		ip6Address = &net.IPNet{IP: healthIPv6, Mask: defaults.ContainerIPv6Mask}
		healthIP = healthIPv6
	}
	if healthIPv4 := node.GetEndpointHealthIPv4(logging.DefaultSlogLogger); healthIPv4 != nil {
		info.Addressing.IPV4 = healthIPv4.String()
		info.Addressing.IPV4PoolName = ipam.PoolDefault().String()
		ip4Address = &net.IPNet{IP: healthIPv4, Mask: defaults.ContainerIPv4Mask}
		healthIP = healthIPv4
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

	ns, err := netns.New()
	if err != nil {
		return nil, fmt.Errorf("create cilium-health netns: %w", err)
	}

	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeVeth:
		_, epLink, err := connector.SetupVethWithNames(logging.DefaultSlogLogger, healthName, epIfaceName, mtuConfig.GetDeviceMTU(),
			bigTCPConfig.GetGROIPv6MaxSize(), bigTCPConfig.GetGSOIPv6MaxSize(),
			bigTCPConfig.GetGROIPv4MaxSize(), bigTCPConfig.GetGSOIPv4MaxSize(),
			info, sysctl)
		if err != nil {
			return nil, fmt.Errorf("Error while creating veth: %w", err)
		}
		if err = netlink.LinkSetNsFd(epLink, int(ns.FD())); err != nil {
			return nil, fmt.Errorf("failed to move device %q to health namespace: %w", epIfaceName, err)
		}
	case datapathOption.DatapathModeNetkit, datapathOption.DatapathModeNetkitL2:
		l2Mode := option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2
		_, epLink, err := connector.SetupNetkitWithNames(logging.DefaultSlogLogger, healthName, epIfaceName, mtuConfig.GetDeviceMTU(),
			bigTCPConfig.GetGROIPv6MaxSize(), bigTCPConfig.GetGSOIPv6MaxSize(),
			bigTCPConfig.GetGROIPv4MaxSize(), bigTCPConfig.GetGSOIPv4MaxSize(), l2Mode,
			info, sysctl)
		if err != nil {
			return nil, fmt.Errorf("Error while creating netkit: %w", err)
		}
		if err = netlink.LinkSetNsFd(epLink, int(ns.FD())); err != nil {
			return nil, fmt.Errorf("failed to move device %q to health namespace: %w", epIfaceName, err)
		}
	}

	if err := ns.Do(func() error {
		return h.configureHealthInterface(epIfaceName, ip4Address, ip6Address)
	}); err != nil {
		return nil, fmt.Errorf("failed configure health interface %q: %w", epIfaceName, err)
	}

	pidfile := filepath.Join(option.Config.StateDir, healthDefaults.PidfilePath)
	args := []string{"--listen", strconv.Itoa(option.Config.ClusterHealthPort), "--pidfile", pidfile}
	cmd.SetTarget(binaryName)
	cmd.SetArgs(args)
	h.logger.Debug("Spawning health endpoint with command",
		logfields.Prog, binaryName,
		logfields.Args, args,
	)

	// Run the health binary inside a netnamespace. Since `Do()` implicitly does
	// `runtime.LockOSThread` the exec'd binary is guaranteed to inherit the
	// correct netnamespace.
	if err := ns.Do(func() error {
		return cmd.Run()
	}); err != nil {
		return nil, err
	}

	// Create the endpoint
	ep, err := endpointCreator.NewEndpointFromChangeModel(baseCtx, info)
	if err != nil {
		return nil, fmt.Errorf("Error while creating endpoint model: %w", err)
	}

	// Wait until the cilium-health endpoint is running before setting up routes
	deadline := time.Now().Add(1 * time.Minute)
	for {
		if _, err := os.Stat(pidfile); err == nil {
			h.logger.Debug("cilium-health agent running", logfields.PIDFile, pidfile)
			break
		} else if time.Now().After(deadline) {
			return nil, fmt.Errorf("Endpoint failed to run: %w", err)
		} else {
			time.Sleep(1 * time.Second)
		}
	}

	// Set up the endpoint routes.
	routes, err := h.getHealthRoutes(node.GetNodeAddressing(logging.DefaultSlogLogger), mtuConfig)
	if err != nil {
		return nil, fmt.Errorf("Error while getting routes for containername %q: %w", info.ContainerName, err)
	}

	err = ns.Do(func() error {
		return h.configureHealthRouting(routes, epIfaceName)
	})
	if err != nil {
		return nil, fmt.Errorf("Error while configuring routes: %w", err)
	}

	if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
		// ENI mode does not support IPv6.
		if err := routingConfig.Configure(
			healthIP,
			mtuConfig.GetDeviceMTU(),
			option.Config.EgressMultiHomeIPRuleCompat,
			false,
		); err != nil {
			return nil, fmt.Errorf("Error while configuring health endpoint rules and routes: %w", err)
		}
	}

	if err := endpointManager.AddEndpoint(ep); err != nil {
		return nil, fmt.Errorf("Error while adding endpoint: %w", err)
	}

	// Give the endpoint a security identity
	ctx, cancel := context.WithTimeout(baseCtx, LaunchTime)
	defer cancel()
	ep.UpdateLabels(ctx, labels.LabelSourceAny, labels.LabelHealth, nil, true)

	// Initialize the health client to talk to this instance.
	client := &Client{host: "http://" + net.JoinHostPort(healthIP.String(), strconv.Itoa(option.Config.ClusterHealthPort))}
	metrics.SubprocessStart.WithLabelValues(ciliumHealth).Inc()

	return client, nil
}

type routingConfigurer interface {
	Configure(ip net.IP, mtu int, compat bool, host bool) error
}
