// Copyright 2017-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package launch

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	healthDefaults "github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/health/probe"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/launcher"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	ciliumHealth = "cilium-health"
	netNSName    = "cilium-health"
	binaryName   = "cilium-health-responder"
)

var (
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

		if ip6Addr != nil {
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
	*probe.Client
}

// PingEndpoint attempts to make an API ping request to the local cilium-health
// endpoint, and returns whether this was successful.
func (c *Client) PingEndpoint() error {
	return c.Client.GetHello()
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
	case option.DatapathModeVeth:
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
	case option.DatapathModeIpvlan:
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
// namespace and attaches it to Cilium the same way as any other endpoint,
// but with special reserved labels.
//
// CleanupEndpoint() must be called before calling LaunchAsEndpoint() to ensure
// cleanup of prior cilium-health endpoint instances.
func LaunchAsEndpoint(baseCtx context.Context, owner regeneration.Owner, n *node.Node, mtuConfig mtu.Configuration, epMgr EndpointAdder) (*Client, error) {
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

	if n.IPv6HealthIP != nil {
		healthIP = n.IPv6HealthIP
		info.Addressing.IPV6 = healthIP.String()
		ip6Address = &net.IPNet{IP: healthIP, Mask: defaults.ContainerIPv6Mask}
	}
	if n.IPv4HealthIP != nil {
		healthIP = n.IPv4HealthIP
		info.Addressing.IPV4 = healthIP.String()
		ip4Address = &net.IPNet{IP: healthIP, Mask: defaults.ContainerIPv4Mask}
	}

	if option.Config.EnableEndpointRoutes {
		dpConfig := &models.EndpointDatapathConfiguration{
			InstallEndpointRoute: true,
			RequireEgressProg:    true,
		}
		info.DatapathConfiguration = dpConfig
	}

	netNS, err := netns.ReplaceNetNSWithName(netNSName)
	if err != nil {
		return nil, err
	}

	switch option.Config.DatapathMode {
	case option.DatapathModeVeth:
		_, epLink, err := connector.SetupVethWithNames(vethName, epIfaceName, mtuConfig.GetDeviceMTU(), info)
		if err != nil {
			return nil, fmt.Errorf("Error while creating veth: %s", err)
		}

		if err = netlink.LinkSetNsFd(*epLink, int(netNS.Fd())); err != nil {
			return nil, fmt.Errorf("failed to move device %q to health namespace: %s", epIfaceName, err)
		}

	case option.DatapathModeIpvlan:
		mapFD, err := connector.CreateAndSetupIpvlanSlave("",
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
		defer unix.Close(mapFD)

	}

	if err = configureHealthInterface(netNS, epIfaceName, ip4Address, ip6Address); err != nil {
		return nil, fmt.Errorf("failed configure health interface %q: %s", epIfaceName, err)
	}

	pidfile := filepath.Join(option.Config.StateDir, PidfilePath)
	prog := "ip"
	args := []string{"netns", "exec", netNSName, binaryName, "--pidfile", pidfile}
	cmd.SetTarget(prog)
	cmd.SetArgs(args)
	log.Infof("Spawning health endpoint with command %q %q", prog, args)
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	// Create the endpoint
	ep, err := endpoint.NewEndpointFromChangeModel(owner, info)
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

	// Set up the endpoint routes
	hostAddressing := node.GetNodeAddressing()
	if err = configureHealthRouting(info.ContainerName, epIfaceName, hostAddressing, mtuConfig); err != nil {
		return nil, fmt.Errorf("Error while configuring routes: %s", err)
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

	// Initialize the health client to talk to this instance. This is why
	// the caller must limit usage of this package to a single goroutine.
	client, err := probe.NewClient("http://" + net.JoinHostPort(healthIP.String(), fmt.Sprintf("%d", healthDefaults.HTTPPathPort)))
	if err != nil {
		return nil, fmt.Errorf("Cannot establish connection to health endpoint: %s", err)
	}
	metrics.SubprocessStart.WithLabelValues(ciliumHealth).Inc()

	return &Client{Client: client}, nil
}
