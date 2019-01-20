// Copyright 2017-2018 Authors of Cilium
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
	"bufio"
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
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"

	"github.com/vishvananda/netlink"
)

const (
	ciliumHealth = "cilium-health"
)

var (
	// vethName is the host-side link device name for cilium-health EP.
	vethName = "cilium_health"

	// vethPeerName is the endpoint-side link device name for cilium-health.
	vethPeerName = "cilium"

	// PidfilePath
	PidfilePath = "health-endpoint.pid"

	// client is used to ping the cilium-health endpoint as a health check.
	client *healthPkg.Client

	// NodeEpAnnotator is used to annotate nodes and pods in a cluster with
	// information about this cilium-health instance.
	NodeEpAnnotator Annotator
)

func logFromCommand(cmd *exec.Cmd, netns string) error {
	scopedLog := log.WithField("netns", netns)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			scopedLog.Debugf("%s", in.Text())
		}
	}()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			scopedLog.Infof("%s", in.Text())
		}
	}()

	return nil
}

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
		log.WithField("netns", netns).WithField("command", cmd).Info("Adding route")
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

// PingEndpoint attempts to make an API ping request to the local cilium-health
// endpoint, and returns whether this was successful.
//
// This function must only be used from the same goroutine as LaunchAsEndpoint().
// It is safe to call PingEndpoint() before LaunchAsEndpoint() so long as the
// goroutine is the same for both calls.
func PingEndpoint() error {
	// client is shared with LaunchAsEndpoint().
	if client == nil {
		return fmt.Errorf("cilium-health endpoint hasn't yet been initialized")
	}
	_, err := client.Restapi.GetHello(nil)
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
		scopedLog := log.WithField(logfields.Path, path).WithError(err)
		scopedLog.Info("Failed to kill previous cilium-health instance")
	}
}

// CleanupEndpoint cleans up remaining resources associated with the health
// endpoint.
//
// This is expected to be called after the process is killed and the endpoint
// is removed from the endpointmanager.
func CleanupEndpoint() {
	scopedLog := log.WithField(logfields.Veth, vethName)
	if link, err := netlink.LinkByName(vethName); err == nil {
		err = netlink.LinkDel(link)
		if err != nil {
			scopedLog.WithError(err).Info("Couldn't delete cilium-health device")
		}
	} else {
		scopedLog.WithError(err).Debug("Didn't find existing device")
	}
}

// Annotator is an interface which describes anything which annotates a node
// with cilium-health metadata.
type Annotator interface {
	AnnotateNode(nodeName string, v4CIDR, v6CIDR *net.IPNet, v4HealthIP, v6HealthIP, v4CiliumHostIP net.IP) error
	AnnotatePod(k8sNamespace, k8sPodName, annotationKey, annotationValue string) error
}

// LaunchAsEndpoint launches the cilium-health agent in a nested network
// namespace and attaches it to Cilium the same way as any other endpoint,
// but with special reserved labels.
//
// CleanupEndpoint() must be called before calling LaunchAsEndpoint() to ensure
// cleanup of prior cilium-health endpoint instances.
func LaunchAsEndpoint(owner endpoint.Owner, hostAddressing *models.NodeAddressing, mtuConfig mtu.Configuration) error {
	var (
		cmd  = launcher.Launcher{}
		info = &models.EndpointChangeRequest{
			ContainerName: ciliumHealth,
			State:         models.EndpointStateWaitingForIdentity,
			Addressing:    &models.AddressPair{},
		}
		ip4, ip6               net.IP
		ip4Address, ip6Address string
	)

	if option.Config.EnableIPv4 {
		ip4 = node.GetIPv4HealthIP()
		info.Addressing.IPV4 = ip4.String()
		ip4WithMask := net.IPNet{IP: ip4, Mask: defaults.ContainerIPv4Mask}
		ip4Address = ip4WithMask.String()
	}

	if option.Config.EnableIPv6 {
		ip6 = node.GetIPv6HealthIP()
		info.Addressing.IPV6 = ip6.String()
		ip6WithMask := net.IPNet{IP: ip6, Mask: defaults.ContainerIPv6Mask}
		ip6Address = ip6WithMask.String()
	}

	if _, _, err := connector.SetupVethWithNames(vethName, vethPeerName, mtuConfig.GetDeviceMTU(), info); err != nil {
		return fmt.Errorf("Error while creating veth: %s", err)
	}

	pidfile := filepath.Join(option.Config.StateDir, PidfilePath)
	healthArgs := fmt.Sprintf("-d --admin=unix --passive --pidfile %s", pidfile)
	args := []string{info.ContainerName, info.InterfaceName, vethPeerName,
		ip6Address, ip4Address, ciliumHealth, healthArgs}
	prog := filepath.Join(option.Config.BpfDir, "spawn_netns.sh")
	cmd.SetTarget(prog)
	cmd.SetArgs(args)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Create the endpoint
	ep, err := endpoint.NewEndpointFromChangeModel(info)
	if err != nil {
		return fmt.Errorf("Error while creating endpoint model: %s", err)
	}
	ep.SetDefaultOpts(option.Config.Opts)

	// Give the endpoint a security identity
	ep.UpdateLabels(owner, labels.LabelHealth, nil, true)

	// Wait until the cilium-health endpoint is running before setting up routes
	deadline := time.Now().Add(1 * time.Minute)
	for {
		if _, err := os.Stat(pidfile); err == nil {
			log.WithField("pidfile", pidfile).Debug("cilium-health agent running")
			break
		} else if time.Now().After(deadline) {
			return fmt.Errorf("Endpoint failed to run: %s", err)
		} else {
			time.Sleep(1 * time.Second)
		}
	}

	// Set up the endpoint routes
	if err = configureHealthRouting(info.ContainerName, vethPeerName, hostAddressing, mtuConfig); err != nil {
		return fmt.Errorf("Error while configuring routes: %s", err)
	}

	if err := endpointmanager.AddEndpoint(owner, ep, "Create cilium-health endpoint"); err != nil {
		return fmt.Errorf("Error while adding endpoint: %s", err)
	}

	if err := ep.LockAlive(); err != nil {
		return err
	}
	if !ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "initial build of health endpoint") {
		endpointmanager.Remove(ep)
		ep.Unlock()
		return fmt.Errorf("unable to transition health endpoint to WaitingToRegenerate state")
	}
	ep.Unlock()

	buildSuccessful := <-ep.Regenerate(owner, &endpoint.ExternalRegenerationMetadata{
		Reason: "health daemon bootstrap",
	})
	if !buildSuccessful {
		endpointmanager.Remove(ep)
		return fmt.Errorf("unable to build health endpoint")
	}

	// Propagate health IPs to all other nodes via annotations
	if NodeEpAnnotator != nil {
		err = NodeEpAnnotator.AnnotateNode(node.GetName(), nil, nil, ip4, ip6, nil)
		if err != nil {
			return fmt.Errorf("Cannot annotate node CIDR range data: %s", err)
		}
	}

	// Initialize the health client to talk to this instance. This is why
	// the caller must limit usage of this package to a single goroutine.
	client, err = healthPkg.NewClient(fmt.Sprintf("tcp://%s:%d", ip4, healthDefaults.HTTPPathPort))
	if err != nil {
		return fmt.Errorf("Cannot establish connection to health endpoint: %s", err)
	}
	metrics.SubprocessStart.WithLabelValues(ciliumHealth).Inc()
	return nil
}
