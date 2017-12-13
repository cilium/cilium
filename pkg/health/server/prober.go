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

package server

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/health/models"
	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"

	"github.com/servak/go-fastping"
	"github.com/sirupsen/logrus"
)

type prober struct {
	*fastping.Pinger
	server *Server

	// 'stop' is closed upon a call to prober.Stop(). When the stopping is
	// finished, then prober.Done() will be notified.
	stop         chan bool
	proberExited chan bool
	done         chan bool

	// The lock protects multiple requests attempting to update the status
	// at the same time - ie, serialize updates between the periodic prober
	// and probes initiated via "GET /status/probe". It is also used to
	// co-ordinate updates of the ICMP responses and the HTTP responses.
	lock.RWMutex
	results map[ipString]*models.PathStatus
	nodes   nodeMap

	// TODO: If nodes leave the cluster, we will never clear out their
	//       entries in the 'results' map.
}

// copyResultRLocked makes a copy of the path status for the specified IP.
func (p *prober) copyResultRLocked(ip string) *models.PathStatus {
	status := p.results[ipString(ip)]
	if status == nil {
		return nil
	}

	result := &models.PathStatus{
		IP: ip,
	}
	paths := map[**models.ConnectivityStatus]*models.ConnectivityStatus{
		&result.Icmp:             status.Icmp,
		&result.HTTP:             status.HTTP,
		&result.HTTPViaL7:        status.HTTPViaL7,
		&result.HTTPViaService:   status.HTTPViaService,
		&result.HTTPViaServiceL7: status.HTTPViaServiceL7,
	}
	for res, value := range paths {
		if value != nil {
			*res = &*value
		}
	}
	return result
}

func getPrimaryIP(node *ciliumModels.NodeElement) string {
	if node.PrimaryAddress.IPV4.Enabled {
		return node.PrimaryAddress.IPV4.IP
	}
	return node.PrimaryAddress.IPV6.IP
}

// getResults gathers a copy of all of the results for nodes currently in the
// cluster.
func (p *prober) getResults() []*models.NodeStatus {
	p.RLock()
	defer p.RUnlock()

	// De-duplicate IPs in 'p.nodes' by building a map based on node.Name.
	resultMap := map[string]*models.NodeStatus{}
	for _, node := range p.nodes {
		if resultMap[node.Name] != nil {
			continue
		}
		primaryIP := getPrimaryIP(node)
		status := &models.NodeStatus{
			Name: node.Name,
			Host: &models.HostStatus{
				PrimaryAddress: p.copyResultRLocked(primaryIP),
			},
			// TODO: Endpoint: &models.PathStatus{},
		}
		secondaryResults := []*models.PathStatus{}
		for _, addr := range node.SecondaryAddresses {
			if addr.Enabled {
				secondaryStatus := p.copyResultRLocked(addr.IP)
				secondaryResults = append(secondaryResults, secondaryStatus)
			}
		}
		status.Host.SecondaryAddresses = secondaryResults
		resultMap[node.Name] = status
	}

	result := []*models.NodeStatus{}
	for _, res := range resultMap {
		result = append(result, res)
	}
	return result
}

func isIPv4(ip string) bool {
	netIP := net.ParseIP(ip)
	return netIP != nil && !strings.Contains(ip, ":")
}

func skipAddress(elem *ciliumModels.NodeAddressingElement) bool {
	return elem == nil || !elem.Enabled || elem.IP == "<nil>"
}

// getAddresses returns a map of the node's addresses -> "primary" bool
func getNodeAddresses(node *ciliumModels.NodeElement) map[*ciliumModels.NodeAddressingElement]bool {
	addresses := map[*ciliumModels.NodeAddressingElement]bool{
		node.PrimaryAddress.IPV4: node.PrimaryAddress.IPV4.Enabled,
		node.PrimaryAddress.IPV6: node.PrimaryAddress.IPV6.Enabled,
	}
	for _, elem := range node.SecondaryAddresses {
		addresses[elem] = false
	}
	return addresses
}

// resolveIP attempts to sanitize 'node' and 'ip', and if successful, returns
// the name of the node and the IP address specified in the addressing element.
// If validation fails or this IP should not be pinged, 'ip' is returned as nil.
func resolveIP(node *ciliumModels.NodeElement, addr *ciliumModels.NodeAddressingElement, proto string, primary bool) (string, *net.IPAddr) {
	if skipAddress(addr) {
		return "", nil
	}

	network := "ip6:icmp"
	if isIPv4(addr.IP) {
		network = "ip4:icmp"
	}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName: node.Name,
		logfields.IPAddr:   addr.IP,
		"primary":          primary,
	})

	ra, err := net.ResolveIPAddr(network, addr.IP)
	if err != nil {
		scopedLog.Debug("Skipping probe for node")
		return "", nil
	}

	scopedLog.WithField("protocol", proto).Debug("Probing for connectivity to node")
	return node.Name, ra
}

// setNodes sets the list of nodes for the prober, and updates the pinger to
// start sending pings to all of the nodes.
// setNodes will steal references to nodes referenced from 'nodes', so the
// caller should not modify them after a call to setNodes.
func (p *prober) setNodes(nodes nodeMap) {
	p.Lock()
	defer p.Unlock()

	for _, n := range nodes {
		for elem, primary := range getNodeAddresses(n) {
			_, addr := resolveIP(n, elem, "icmp", primary)

			ip := ipString(elem.IP)
			result := &models.ConnectivityStatus{}
			if addr == nil {
				result.Status = "Failed to resolve IP"
			} else {
				result.Status = "Connection timed out"
				p.AddIPAddr(addr)
				p.nodes[ip] = n
			}

			if p.results[ip] == nil {
				p.results[ip] = &models.PathStatus{
					IP: elem.IP,
				}
			}
			p.results[ip].Icmp = result
		}
	}
}

func (p *prober) httpProbe(node string, ip string, port int) *models.ConnectivityStatus {
	result := &models.ConnectivityStatus{}

	host := fmt.Sprintf("http://%s:%d", ip, port)
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName: node,
		logfields.IPAddr:   ip,
		"host":             host,
		"path":             PortToPaths[port],
	})

	client, err := client.NewClient(host)
	if err == nil {
		scopedLog.Debug("Greeting host")
		start := time.Now()
		_, err = client.Restapi.GetHello(nil)
		rtt := time.Since(start)
		if err == nil {
			scopedLog.WithField("rtt", rtt).Debug("Greeting successful")
			result.Status = ""
			result.Latency = rtt.Nanoseconds()
		} else {
			scopedLog.WithError(err).Debug("Greeting snubbed")
			result.Status = "Connection timed out"
		}
	} else {
		scopedLog.WithError(err).Info("Failed to express greeting to host")
		result.Status = err.Error()
	}

	return result
}

func (p *prober) runHTTPProbe() {
	nodes := make(map[string]*net.IPAddr)
	p.RLock()
	for _, node := range p.nodes {
		for elem, primary := range getNodeAddresses(node) {
			if name, addr := resolveIP(node, elem, "icmp", primary); addr != nil {
				nodes[name] = addr
			}
		}
	}
	p.RUnlock()

	for name, ip := range nodes {
		status := &models.PathStatus{}
		ports := map[int]**models.ConnectivityStatus{
			defaults.HTTPPathPort: &status.HTTP,
		}
		for port, result := range ports {
			*result = p.httpProbe(name, ip.String(), port)
			if status.HTTP.Status != "" {
				log.WithFields(logrus.Fields{
					logfields.NodeName: name,
					logfields.IPAddr:   ip.String(),
					logfields.Port:     port,
				}).Debugf("Failed to probe: %s", status.HTTP.Status)
			}
		}

		p.Lock()
		p.results[ipString(ip.String())].HTTP = status.HTTP
		p.Unlock()
	}
}

// Done returns a channel that is closed when RunLoop() is stopped by an error.
// It must be called after the RunLoop() call.
func (p *prober) Done() <-chan bool {
	return p.done
}

// Run sends a single probes out to all of the other cilium nodes to gather
// connectivity status for the cluster.
func (p *prober) Run() error {
	err := p.Pinger.Run()
	p.runHTTPProbe()
	return err
}

// Stop disrupts the currently running RunLoop(). This may only be called after
// a call to RunLoop().
func (p *prober) Stop() {
	p.Pinger.Stop()
	close(p.stop)
	<-p.proberExited
	close(p.done)
}

// RunLoop periodically sends probes out to all of the other cilium nodes to
// gather connectivity status for the cluster.
//
// This is a non-blocking method so it immediately returns. If you want to
// stop sending packets, call Stop().
func (p *prober) RunLoop() {
	// FIXME: Spread the probes out across the probing interval
	p.Pinger.RunLoop()

	go func() {
		tick := time.NewTicker(p.server.ProbeInterval)
	loop:
		for {
			select {
			case <-p.stop:
				break loop
			case <-tick.C:
				p.runHTTPProbe()
				continue
			}
		}
		tick.Stop()
		close(p.proberExited)
	}()
}

// newPinger prepares a prober. The caller may invoke one the Run* methods of
// the prober to populate its 'results' map.
func newProber(s *Server, nodes nodeMap) *prober {
	prober := &prober{
		Pinger:       fastping.NewPinger(),
		server:       s,
		done:         make(chan bool),
		proberExited: make(chan bool),
		stop:         make(chan bool),
		results:      make(map[ipString]*models.PathStatus),
		nodes:        nodes,
	}
	prober.MaxRTT = s.ProbeDeadline

	prober.setNodes(nodes)
	prober.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		prober.RLock()
		node := prober.nodes[ipString(addr.String())]
		prober.RUnlock()

		scopedLog := log.WithFields(logrus.Fields{
			logfields.IPAddr: addr,
			"rtt":            rtt,
		})
		if node == nil {
			scopedLog.Debugf("Node disappeared, skip result")
			return
		}

		prober.Lock()
		prober.results[ipString(addr.String())].Icmp = &models.ConnectivityStatus{
			Latency: rtt.Nanoseconds(),
			Status:  "",
		}
		prober.Unlock()

		scopedLog.WithFields(logrus.Fields{
			logfields.NodeName: node.Name,
		}).Debugf("Probe successful")
	}

	return prober
}
