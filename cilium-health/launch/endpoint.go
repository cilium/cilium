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
	"github.com/cilium/cilium/pkg/endpointmanager"
	healthPkg "github.com/cilium/cilium/pkg/health/client"
	healthDefaults "github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/launcher"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	ciliumHealth = "cilium-health"
	netNSName    = "cilium-health"
)

var (
	// vethName is the host-side veth link device name for cilium-health EP
	// (veth mode only).
	vethName = "cilium_health"

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

// Client wraps a client to a specific cilium-health endpoint instance, to
// provide convenience methods such as PingEndpoint().
type Client struct {
	*healthPkg.Client
}

// PingEndpoint attempts to make an API ping request to the local cilium-health
// endpoint, and returns whether this was successful.
func (c *Client) PingEndpoint() error {
	_, err := c.Restapi.GetHello(nil)
	return err
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
	if err := pidfile.Kill(path); err != nil {
		log.WithField(logfields.Path, path).WithError(err).
			Warning("Failed to kill cilium-health instance")
	}
}

// CleanupEndpoint cleans up remaining resources associated with the health
// endpoint.
//
// This is expected to be called after the process is killed and the endpoint
// is removed from the endpointmanager.
func CleanupEndpoint() {
	// In the case of ipvlan, the ipvlan slave device is removed by removal
	// of the endpoint netns in "cleanup" of spawn_netns.sh
	if option.Config.DatapathMode == option.DatapathModeVeth {
		scopedLog := log.WithField(logfields.Veth, vethName)
		if link, err := netlink.LinkByName(vethName); err == nil {
			err = netlink.LinkDel(link)
			if err != nil {
				scopedLog.WithError(err).Warning("Couldn't delete cilium-health device")
			}
		} else {
			scopedLog.WithError(err).Debug("Didn't find existing device")
		}
	}
}

// LaunchAsEndpoint launches the cilium-health agent in a nested network
// namespace and attaches it to Cilium the same way as any other endpoint,
// but with special reserved labels.
//
// CleanupEndpoint() must be called before calling LaunchAsEndpoint() to ensure
// cleanup of prior cilium-health endpoint instances.
func LaunchAsEndpoint(baseCtx context.Context, owner endpoint.Owner, n *node.Node, mtuConfig mtu.Configuration) (*Client, error) {
	var (
		cmd  = launcher.Launcher{}
		info = &models.EndpointChangeRequest{
			ContainerName: ciliumHealth,
			State:         models.EndpointStateWaitingForIdentity,
			Addressing:    &models.AddressPair{},
		}
		ip4Address, ip6Address string
		healthIP               net.IP
		hostIfaceName          string
	)

	if n.IPv4HealthIP != nil {
		healthIP = n.IPv4HealthIP
		info.Addressing.IPV4 = healthIP.String()
		ip4WithMask := net.IPNet{IP: healthIP, Mask: defaults.ContainerIPv4Mask}
		ip4Address = ip4WithMask.String()
	}

	if n.IPv6HealthIP != nil {
		healthIP = n.IPv6HealthIP
		info.Addressing.IPV6 = healthIP.String()
		ip6WithMask := net.IPNet{IP: healthIP, Mask: defaults.ContainerIPv6Mask}
		ip6Address = ip6WithMask.String()
	}

	switch option.Config.DatapathMode {
	case option.DatapathModeVeth:
		if _, _, err := connector.SetupVethWithNames(vethName, epIfaceName, mtuConfig.GetDeviceMTU(), info); err != nil {
			return nil, fmt.Errorf("Error while creating veth: %s", err)
		}
		hostIfaceName = vethName

	case option.DatapathModeIpvlan:
		netNS, err := netns.ReplaceNetNSWithName(netNSName)
		if err != nil {
			return nil, err
		}

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

		hostIfaceName = option.Config.Device
	}

	pidfile := filepath.Join(option.Config.StateDir, PidfilePath)
	healthArgs := fmt.Sprintf("-d --admin=unix --passive --pidfile %s", pidfile)
	args := []string{info.ContainerName, hostIfaceName, epIfaceName,
		ip6Address, ip4Address, ciliumHealth, healthArgs}
	if option.Config.DatapathMode == option.DatapathModeIpvlan {
		// Do not initialize netns (i.e. create and move the slave to it), as
		// otherwise qdisc of the slave will get reset
		args = append(args, "--skip-netns-init")
	}
	prog := filepath.Join(option.Config.BpfDir, "spawn_netns.sh")
	cmd.SetTarget(prog)
	cmd.SetArgs(args)
	log.Infof("Spawning health endpoint with arguments %#v", args)
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	// Create the endpoint
	ep, err := endpoint.NewEndpointFromChangeModel(owner.GetPolicyRepository(), info)
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

	if err := endpointmanager.AddEndpoint(owner, ep, "Create cilium-health endpoint"); err != nil {
		return nil, fmt.Errorf("Error while adding endpoint: %s", err)
	}

	if err := ep.LockAlive(); err != nil {
		return nil, err
	}
	ep.PinDatapathMap()
	ep.Unlock()

	// Give the endpoint a security identity
	ctx, cancel := context.WithTimeout(baseCtx, LaunchTime)
	defer cancel()
	ep.UpdateLabels(ctx, owner, labels.LabelHealth, nil, true)

	// Initialize the health client to talk to this instance. This is why
	// the caller must limit usage of this package to a single goroutine.
	client, err := healthPkg.NewClient("tcp://" + net.JoinHostPort(healthIP.String(), fmt.Sprintf("%d", healthDefaults.HTTPPathPort)))
	if err != nil {
		return nil, fmt.Errorf("Cannot establish connection to health endpoint: %s", err)
	}
	metrics.SubprocessStart.WithLabelValues(ciliumHealth).Inc()

	return &Client{Client: client}, nil
}
