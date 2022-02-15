// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/servak/go-fastping"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/health/models"
	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/health/probe"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// healthReport is a snapshot of the health of the cluster.
type healthReport struct {
	startTime time.Time
	nodes     []*models.NodeStatus
}

type prober struct {
	*fastping.Pinger
	server *Server

	// 'stop' is closed upon a call to prober.Stop(). When the stopping is
	// finished, then prober.Done() will be notified.
	stop         chan bool
	proberExited chan bool

	// The lock protects multiple requests attempting to update the status
	// at the same time - ie, serialize updates between the periodic prober
	// and probes initiated via "GET /status/probe". It is also used to
	// co-ordinate updates of the ICMP responses and the HTTP responses.
	lock.RWMutex

	// start is the start time for the current probe cycle.
	start   time.Time
	results map[ipString]*models.PathStatus
	nodes   nodeMap
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
		&result.Icmp: status.Icmp,
		&result.HTTP: status.HTTP,
	}
	for res, value := range paths {
		if value != nil {
			*res = value
		}
	}
	return result
}

// getResults gathers a copy of all of the results for nodes currently in the
// cluster.
func (p *prober) getResults() *healthReport {
	p.RLock()
	defer p.RUnlock()

	// De-duplicate IPs in 'p.nodes' by building a map based on node.Name.
	resultMap := map[string]*models.NodeStatus{}
	for _, node := range p.nodes {
		if resultMap[node.Name] != nil {
			continue
		}
		primaryIP := node.PrimaryIP()
		primaryHealthIP := node.HealthIP()

		secondaryAddresses := []*models.PathStatus{}
		for _, ip := range node.SecondaryIPs() {
			if addr := p.copyResultRLocked(ip); addr != nil {
				secondaryAddresses = append(secondaryAddresses, addr)
			}
		}

		status := &models.NodeStatus{
			Name: node.Name,
			Host: &models.HostStatus{
				PrimaryAddress:     p.copyResultRLocked(primaryIP),
				SecondaryAddresses: secondaryAddresses,
			},
		}

		secondaryEndpointAddresses := []*models.PathStatus{}
		for _, ip := range node.SecondaryHealthIPs() {
			if addr := p.copyResultRLocked(ip); addr != nil {
				secondaryEndpointAddresses = append(secondaryEndpointAddresses, addr)
			}
		}

		if primaryHealthIP != "" {
			primaryEndpointAddress := p.copyResultRLocked(primaryHealthIP)
			status.Endpoint = primaryEndpointAddress
			status.HealthEndpoint = &models.EndpointStatus{
				PrimaryAddress:     primaryEndpointAddress,
				SecondaryAddresses: secondaryEndpointAddresses,
			}
		}

		resultMap[node.Name] = status
	}

	result := &healthReport{startTime: p.start}
	for _, res := range resultMap {
		result.nodes = append(result.nodes, res)
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

// resolveIP attempts to sanitize 'node' and 'ip', and if successful, returns
// the name of the node and the IP address specified in the addressing element.
// If validation fails or this IP should not be pinged, 'ip' is returned as nil.
func resolveIP(n *healthNode, addr *ciliumModels.NodeAddressingElement, proto string, primary bool) (string, *net.IPAddr) {
	node := n.NodeElement
	network := "ip6:icmp"
	if isIPv4(addr.IP) {
		network = "ip4:icmp"
	}
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName: node.Name,
		logfields.IPAddr:   addr.IP,
		"primary":          primary,
	})

	if skipAddress(addr) {
		scopedLog.Debug("Skipping probe for address")
		return "", nil
	}

	ra, err := net.ResolveIPAddr(network, addr.IP)
	if err != nil {
		scopedLog.Debug("Unable to resolve address")
		return "", nil
	}

	scopedLog.WithField("protocol", proto).Debug("Probing for connectivity to node")
	return node.Name, ra
}

// RemoveIP removes all traces of the specified IP from the prober, including
// clearing all cached results, mapping from this IP to a node, and entries in
// the ICMP and TCP pingers.
func (p *prober) RemoveIP(ip string) {
	nodeIP := ipString(ip)
	delete(p.results, nodeIP)
	p.Pinger.RemoveIP(ip)   // ICMP pinger
	delete(p.nodes, nodeIP) // TCP prober
}

// setNodes sets the list of nodes for the prober, and updates the pinger to
// start sending pings to all nodes added.
// 'removed' nodes will be removed from the pinger to stop sending pings to
// those removed nodes.
// setNodes will steal references to nodes referenced from 'added', so the
// caller should not modify them after a call to setNodes.
// If a node is updated, it will appear in both maps and will be removed then
// added (potentially with different information).
func (p *prober) setNodes(added nodeMap, removed nodeMap) {
	p.Lock()
	defer p.Unlock()

	for _, n := range removed {
		for elem := range n.Addresses() {
			p.RemoveIP(elem.IP)
		}
	}

	for _, n := range added {
		for elem, primary := range n.Addresses() {
			_, addr := resolveIP(&n, elem, "icmp", primary)
			if addr == nil {
				continue
			}

			ip := ipString(elem.IP)
			result := &models.ConnectivityStatus{}
			result.Status = "Connection timed out"
			p.AddIPAddr(addr)
			p.nodes[ip] = n

			if p.results[ip] == nil {
				p.results[ip] = &models.PathStatus{
					IP: elem.IP,
				}
			}
			p.results[ip].Icmp = result
		}
	}
}

const httpPathDescription = "Via L3"

func (p *prober) httpProbe(node string, ip string) *models.ConnectivityStatus {
	result := &models.ConnectivityStatus{}

	host := "http://" + net.JoinHostPort(ip, strconv.Itoa(p.server.Config.HTTPPathPort))
	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName: node,
		logfields.IPAddr:   ip,
		"host":             host,
		"path":             httpPathDescription,
	})

	scopedLog.Debug("Greeting host")
	start := time.Now()
	err := probe.GetHello(host)
	rtt := time.Since(start)
	if err == nil {
		scopedLog.WithField("rtt", rtt).Debug("Greeting successful")
		result.Status = ""
		result.Latency = rtt.Nanoseconds()
	} else {
		scopedLog.WithError(err).Debug("Greeting failed")
		result.Status = err.Error()
	}

	return result
}

func (p *prober) getIPsByNode() map[string][]*net.IPAddr {
	p.RLock()
	defer p.RUnlock()

	// p.nodes is mapped from all known IPs -> nodes in N:M configuration,
	// so multiple IPs could refer to the same node. To ensure we only
	// ping each node once, deduplicate nodes into map of nodeName -> []IP.
	nodes := make(map[string][]*net.IPAddr)
	for _, node := range p.nodes {
		if nodes[node.Name] != nil {
			// Already handled this node.
			continue
		}
		nodes[node.Name] = []*net.IPAddr{}
		for elem, primary := range node.Addresses() {
			if _, addr := resolveIP(&node, elem, "http", primary); addr != nil {
				nodes[node.Name] = append(nodes[node.Name], addr)
			}
		}
	}

	return nodes
}

func (p *prober) runHTTPProbe() {
	startTime := time.Now()
	p.Lock()
	p.start = startTime
	p.Unlock()

	for name, ips := range p.getIPsByNode() {
		for _, ip := range ips {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.NodeName: name,
				logfields.IPAddr:   ip.String(),
			})

			resp := p.httpProbe(name, ip.String())
			if resp.Status != "" {
				scopedLog.WithFields(logrus.Fields{
					logfields.Port: p.server.Config.HTTPPathPort,
				}).Debugf("Failed to probe: %s", resp.Status)
			}

			peer := ipString(ip.String())
			p.Lock()
			if _, ok := p.results[peer]; ok {
				p.results[peer].HTTP = resp
			} else {
				// While we weren't holding the lock, the
				// pinger's OnIdle() callback fired and updated
				// the set of nodes to remove this node.
				scopedLog.Debug("Node disappeared before result written")
			}
			p.Unlock()
		}
	}
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
		proberExited: make(chan bool),
		stop:         make(chan bool),
		results:      make(map[ipString]*models.PathStatus),
		nodes:        make(nodeMap),
	}
	prober.MaxRTT = s.ProbeDeadline
	// FIXME: Doubling the default payload size to 16 is a workaround for GH-18177
	prober.Size = 2 * fastping.TimeSliceLength
	prober.setNodes(nodes, nil)
	prober.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		prober.Lock()
		defer prober.Unlock()
		node, exists := prober.nodes[ipString(addr.String())]

		scopedLog := log.WithFields(logrus.Fields{
			logfields.IPAddr: addr,
			"rtt":            rtt,
		})
		if !exists {
			scopedLog.Debugf("Node disappeared, skip result")
			return
		}

		prober.results[ipString(addr.String())].Icmp = &models.ConnectivityStatus{
			Latency: rtt.Nanoseconds(),
			Status:  "",
		}
		scopedLog.WithFields(logrus.Fields{
			logfields.NodeName: node.Name,
		}).Debugf("Probe successful")
	}

	return prober
}
