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
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/plugins"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/vishvananda/netlink"
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
	v4Routes, err := plugins.IPv4Routes(addressing)
	if err == nil {
		routes = append(routes, v4Routes...)
	} else {
		log.Debugf("Couldn't get IPv4 routes for health routing")
	}
	v6Routes, err := plugins.IPv6Routes(addressing)
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

// LaunchAsEndpoint launches the cilium-health agent in a nested network
// namespace and attaches it to Cilium the same way as any other endpoint,
// but with special reserved labels.
func LaunchAsEndpoint(owner endpoint.Owner, hostAddressing *models.NodeAddressing, opts *option.BoolOptions) context.CancelFunc {
	ip4 := node.GetIPv4HealthIP()
	ip6 := node.GetIPv6HealthIP()

	// Prepare the endpoint change request
	id := int64(addressing.CiliumIPv6(ip6).EndpointID())
	info := &models.EndpointChangeRequest{
		ID:            id,
		ContainerID:   endpoint.NewCiliumID(id),
		ContainerName: "cilium-health",
		State:         models.EndpointStateWaitingForIdentity,
		Addressing: &models.AddressPair{
			IPV6: ip6.String(),
			IPV4: ip4.String(),
		},
	}

	// Create the veth pair for the health endpoint
	vethName := "cilium_health"
	vethPeerName := "cilium"
	if link, err := netlink.LinkByName(vethName); err == nil {
		netlink.LinkDel(link)
	} else {
		log.Debug("Didn't find existing link")
	}
	veth, _, err := plugins.SetupVethWithNames(vethName, vethPeerName, 1450, info)
	if err != nil {
		log.WithError(err).Fatal("Error while creating cilium-health veth")
	}
	defer func() {
		if err == nil {
			return
		}
		if err = netlink.LinkDel(veth); err != nil {
			log.WithError(err).WithField(logfields.Veth, veth.Name).Warn("failed to clean up veth")
		}
	}()

	// Invoke spawn_netns.sh to spin up the health endpoint
	pidfile := filepath.Join(owner.GetStateDir(), "health-endpoint.pid")
	if pid, err := ioutil.ReadFile(pidfile); err == nil {
		// Existing cilium-health exists, kill it so we can create a
		// new one and steal all its logs (om nom nom!)
		pidInt, err := strconv.Atoi(string(pid))
		if err == nil {
			log.WithField("pid", pidInt).Debug("Killing existing cilium-health instance")
			if oldProc, err := os.FindProcess(pidInt); err == nil {
				oldProc.Kill()
			}
		}
	}
	os.RemoveAll(pidfile)
	healthArgs := fmt.Sprintf("-d --admin=unix --passive --pidfile %s", pidfile)
	args := []string{info.ContainerName, info.InterfaceName, vethPeerName,
		ip6.String(), ip4.String(), "cilium-health", healthArgs}
	prog := filepath.Join(owner.GetBpfDir(), "spawn_netns.sh")

	ctx, cancelHealth := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, prog, args...)
	if err = logFromCommand(cmd, info.ContainerName); err != nil {
		log.WithError(err).Fatal("Error while opening pipes to health endpoint")
	}
	if err = cmd.Start(); err != nil {
		target := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", target).WithError(err).Fatal("Error spawning cilium-health endpoint")
	}

	// Create the endpoint
	lbl := labels.Labels{labels.IDNameHealth: labels.NewLabel(labels.IDNameHealth, "", labels.LabelSourceReserved)}
	ep, err := endpoint.NewEndpointFromChangeModel(info, lbl)
	if err != nil {
		log.WithError(err).Fatal("Error while creating cilium-health endpoint")
	}
	ep.SetDefaultOpts(opts)

	// Add the endpoint
	if err := endpointmanager.AddEndpoint(owner, ep, "Create cilium-health endpoint"); err != nil {
		log.WithError(err).Fatal("Error while adding cilium-health endpoint")
	}

	// Give the endpoint a security identity
	if errLabelsAdd := ep.ModifyIdentityLabels(owner, lbl, labels.Labels{}); errLabelsAdd != nil {
		log.WithError(errLabelsAdd).Fatal("Failed to set labels on cilium-health endpoint")
	}

	// Wait until the cilium-health endpoint is running before setting up routes
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(pidfile); err == nil {
			log.WithField("pidfile", pidfile).Debug("cilium-health agent running")
			break
		} else if time.Now().After(deadline) {
			log.WithError(err).Fatal("Cilium endpoint failed to run")
			break
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Set up the endpoint routes
	if err = configureHealthRouting(info.ContainerName, vethPeerName, hostAddressing); err != nil {
		log.WithError(err).Fatal("Error while configuring cilium-health routes")
	}

	// Propagate health IPs to all other nodes
	if k8s.IsEnabled() {
		err := k8s.AnnotateNode(k8s.Client(), node.GetName(), nil, nil, ip4, ip6)
		if err != nil {
			log.WithError(err).Fatal("Cannot annotate node CIDR range data")
		}
	}

	return func() {
		cancelHealth()
		netlink.LinkDel(veth)
	}
}
