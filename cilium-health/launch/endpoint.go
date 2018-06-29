// Copyright 2017 Authors of Cilium
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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/plugins"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpointmanager"
	healthPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/vishvananda/netlink"
)

var (
	// vethName is the host-side link device name for cilium-health EP.
	vethName = "cilium_health"

	// vethPeerName is the endpoint-side link device name for cilium-health.
	vethPeerName = "cilium"

	// healthPidfile
	healthPidfile = "health-endpoint.pid"

	// client is used to ping the cilium-health endpoint as a health check.
	client *healthPkg.Client
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

func configureHealthRouting(netns, dev string, addressing *models.NodeAddressing) error {
	routes := []plugins.Route{}
	v4Routes, err := plugins.IPv4Routes(addressing, mtu.StandardMTU)
	if err == nil {
		routes = append(routes, v4Routes...)
	} else {
		log.Debugf("Couldn't get IPv4 routes for health routing")
	}
	v6Routes, err := plugins.IPv6Routes(addressing, mtu.StandardMTU)
	if err != nil {
		return fmt.Errorf("Failed to get IPv6 routes")
	}
	routes = append(routes, v6Routes...)

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

// CleanupEndpoint attempts to kill any existing cilium-health endpoint and
// clean up its devices and pidfiles. If any existing cilium-health endpoint
// exists in Cilium, it is removed from the endpoint manager.
//
// This is intended to be invoked in multiple situations:
// * The health endpoint has never been run before
// * The health endpoint was run during a previous run of the Cilium agent
// * The health endpoint crashed during the current run of the Cilium agent
//   and needs to be cleaned up before it is restarted.
func CleanupEndpoint(owner endpoint.Owner) {
	path := filepath.Join(option.Config.StateDir, healthPidfile)
	if err := pidfile.Kill(path); err != nil {
		scopedLog := log.WithField(logfields.Path, path).WithError(err)
		scopedLog.Info("Failed to kill previous cilium-health instance")
	}

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

// LaunchAsEndpoint launches the cilium-health agent in a nested network
// namespace and attaches it to Cilium the same way as any other endpoint,
// but with special reserved labels.
//
// CleanupEndpoint() must be called before calling LaunchAsEndpoint() to ensure
// cleanup of prior cilium-health endpoint instances.
func LaunchAsEndpoint(owner endpoint.Owner, hostAddressing *models.NodeAddressing) error {

	ip4 := node.GetIPv4HealthIP()
	ip6 := node.GetIPv6HealthIP()

	// Prepare the endpoint change request
	id := int64(addressing.CiliumIPv6(ip6).EndpointID())
	info := &models.EndpointChangeRequest{
		ID:            id,
		ContainerID:   endpointid.NewCiliumID(id),
		ContainerName: "cilium-health",
		State:         models.EndpointStateWaitingForIdentity,
		Addressing: &models.AddressPair{
			IPV6: ip6.String(),
			IPV4: ip4.String(),
		},
	}

	// Increment initial state counters for cilium-health endpoint
	// since it does not follow the createEndpoint flow like
	// other endpoints.
	metrics.EndpointStateCount.
		WithLabelValues(endpoint.StateWaitingForIdentity).Inc()

	if _, _, err := plugins.SetupVethWithNames(vethName, vethPeerName, mtu.StandardMTU, info); err != nil {
		return fmt.Errorf("Error while creating veth: %s", err)
	}

	pidfile := filepath.Join(option.Config.StateDir, healthPidfile)
	healthArgs := fmt.Sprintf("-d --admin=unix --passive --pidfile %s", pidfile)
	args := []string{info.ContainerName, info.InterfaceName, vethPeerName,
		ip6.String(), ip4.String(), "cilium-health", healthArgs}
	prog := filepath.Join(owner.GetBpfDir(), "spawn_netns.sh")

	cmd := exec.CommandContext(context.Background(), prog, args...)
	if err := logFromCommand(cmd, info.ContainerName); err != nil {
		return fmt.Errorf("Error while opening pipes to health endpoint: %s", err)
	}
	if err := cmd.Start(); err != nil {
		target := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		return fmt.Errorf("Error spawning endpoint (%q): %s", target, err)
	}

	// Create the endpoint
	ep, err := endpoint.NewEndpointFromChangeModel(info)
	if err != nil {
		return fmt.Errorf("Error while creating endpoint model: %s", err)
	}
	ep.SetDefaultOpts(option.Config.Opts)

	// Give the endpoint a security identity
	lbls := labels.Labels{labels.IDNameHealth: labels.NewLabel(labels.IDNameHealth, "", labels.LabelSourceReserved)}
	ep.SetIdentityLabels(owner, lbls)

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
	if err = configureHealthRouting(info.ContainerName, vethPeerName, hostAddressing); err != nil {
		return fmt.Errorf("Error while configuring routes: %s", err)
	}

	// Add the endpoint
	if err := endpointmanager.AddEndpoint(owner, ep, "Create cilium-health endpoint"); err != nil {
		return fmt.Errorf("Error while adding endpoint: %s", err)
	}

	// Propagate health IPs to all other nodes
	if k8s.IsEnabled() {
		err := k8s.AnnotateNode(k8s.Client(), node.GetName(), nil, nil, ip4, ip6)
		if err != nil {
			return fmt.Errorf("Cannot annotate node CIDR range data: %s", err)
		}
	}

	// Initialize the health client to talk to this instance. This is why
	// the caller must limit usage of this package to a single goroutine.
	client, err = healthPkg.NewClient(fmt.Sprintf("tcp://%s:%d", ip4, defaults.HTTPPathPort))
	if err != nil {
		return fmt.Errorf("Cannot establish connection to health endpoint: %s", err)
	}

	return nil
}
