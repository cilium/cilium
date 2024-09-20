// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"net"
	"strconv"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/health/models"
	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/health/probe"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// healthReport is a snapshot of the health of the cluster.
type healthReport struct {
	startTime time.Time
	nodes     []*models.NodeStatus
}

type prober struct {
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
func resolveIP(n *healthNode, addr *ciliumModels.NodeAddressingElement, primary bool) (string, *net.IPAddr) {
	node := n.NodeElement
	network := "ip6:icmp"
	if isIPv4(addr.IP) {
		network = "ip4:icmp"
	}

	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	scopedLog := log
	if logging.CanLogAt(scopedLog.Logger, logrus.DebugLevel) {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.NodeName: node.Name,
			logfields.IPAddr:   addr.IP,
			"primary":          primary,
		})
	}

	if skipAddress(addr) {
		scopedLog.Debug("Skipping probe for address")
		return "", nil
	}

	ra, err := net.ResolveIPAddr(network, addr.IP)
	if err != nil || ra.String() == "" {
		scopedLog.Debug("Unable to resolve address")
		return "", nil
	}

	scopedLog.Debug("Probing for connectivity to node")
	return node.Name, ra
}

// RemoveIP removes all traces of the specified IP from the prober, including
// clearing all cached results, mapping from this IP to a node, and entries in
// the ICMP and TCP pingers.
func (p *prober) RemoveIP(ip string) {
	nodeIP := ipString(ip)
	delete(p.results, nodeIP)
	delete(p.nodes, nodeIP)
}

// setNodes sets the list of nodes for the prober, and updates the pinger to
// start sending pings to all nodes added.
// 'removed' nodes will be removed from the pinger to stop sending pings to
// those removed nodes.
// setNodes will steal references to nodes referenced from 'added', so the
// caller should not modify them after a call to setNodes.
// If a node is updated, it will appear in both maps and will be removed then
// added (potentially with different information). We want to do it only if relevant
// health-information changes to preserve previous health-checking results.
func (p *prober) setNodes(added nodeMap, removed nodeMap) {
	p.Lock()
	defer p.Unlock()

	// Check what IPs will be readded
	// so we don't remove results that we already have for them.
	readdedIPs := map[string]struct{}{}
	for _, n := range added {
		for elem, primary := range n.Addresses() {
			_, addr := resolveIP(&n, elem, primary)
			if addr == nil {
				continue
			}
			readdedIPs[elem.IP] = struct{}{}
		}
	}

	for _, n := range removed {
		for elem := range n.Addresses() {
			if _, ok := readdedIPs[elem.IP]; !ok {
				p.RemoveIP(elem.IP)
			}
		}
	}

	for _, n := range added {
		for elem, primary := range n.Addresses() {
			_, addr := resolveIP(&n, elem, primary)
			if addr == nil {
				continue
			}

			ip := ipString(elem.IP)
			p.nodes[ip] = n

			if p.results[ip] == nil {
				p.results[ip] = &models.PathStatus{
					IP: elem.IP,
				}
			}
		}
	}
}

const httpPathDescription = "Via L3"

func (p *prober) httpProbe(node string, ip string) *models.ConnectivityStatus {
	result := &models.ConnectivityStatus{}

	host := "http://" + net.JoinHostPort(ip, strconv.Itoa(p.server.Config.HTTPPathPort))

	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	scopedLog := log
	debugLogsEnabled := logging.CanLogAt(scopedLog.Logger, logrus.DebugLevel)
	if debugLogsEnabled {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.NodeName: node,
			logfields.IPAddr:   ip,
			"host":             host,
			"path":             httpPathDescription,
		})
	}

	scopedLog.Debug("Greeting host")
	start := time.Now()
	err := probe.GetHello(host)
	rtt := time.Since(start)
	if err == nil {
		if debugLogsEnabled {
			scopedLog.WithField("rtt", rtt).Debug("Greeting successful")
		}

		result.Status = ""
		result.Latency = rtt.Nanoseconds()
	} else {
		if debugLogsEnabled {
			scopedLog.WithError(err).Debug("Greeting failed")
		}

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
			if _, addr := resolveIP(&node, elem, primary); addr != nil {
				nodes[node.Name] = append(nodes[node.Name], addr)
			}
		}
	}

	return nodes
}

func (p *prober) icmpPing(node string, ip string) *models.ConnectivityStatus {
	result := &models.ConnectivityStatus{}

	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	scopedLog := log
	debugLogsEnabled := logging.CanLogAt(scopedLog.Logger, logrus.DebugLevel)
	if debugLogsEnabled {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.NodeName: node,
			logfields.IPAddr:   ip,
		})
	}

	scopedLog.Debug("Pinging host")
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		if debugLogsEnabled {
			scopedLog.WithError(err).Debug("Failed to create pinger")
		}
		result.Status = err.Error()
		return result
	}
	pinger.Timeout = p.server.ProbeDeadline
	pinger.Count = 1
	pinger.OnFinish = func(stats *probing.Statistics) {
		p.Lock()
		defer p.Unlock()

		if stats.PacketsRecv > 0 && len(stats.Rtts) > 0 {
			if debugLogsEnabled {
				scopedLog.WithField("rtt", stats.Rtts[0].Nanoseconds()).Debug("Ping successful")
			}
			result.Latency = stats.Rtts[0].Nanoseconds()
			result.Status = ""
		} else {
			scopedLog.Debug("Ping failed")
			result.Status = "Connection timed out"
		}
	}
	err = pinger.Run()
	if err != nil {
		scopedLog.Debugf("Failed to run pinger for IP %s: %v", ip, err)
		result.Status = err.Error()
	}
	return result
}

func (p *prober) runHTTPProbe() {
	startTime := time.Now()
	p.Lock()
	p.start = startTime
	p.Unlock()

	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	debugLogsEnabled := logging.CanLogAt(log.Logger, logrus.DebugLevel)

	for name, ips := range p.getIPsByNode() {
		scopedLog := log

		if debugLogsEnabled {
			scopedLog = log.WithField(logfields.NodeName, name)
		}

		for _, ip := range ips {
			if debugLogsEnabled {
				scopedLog = scopedLog.WithFields(logrus.Fields{
					logfields.IPAddr: ip.String(),
					logfields.Port:   p.server.Config.HTTPPathPort,
				})
			}

			resp := p.httpProbe(name, ip.String())
			if resp.Status != "" {
				scopedLog.Debugf("Failed to probe: %s", resp.Status)
			}

			peer := ipString(ip.String())
			p.Lock()
			if _, ok := p.results[peer]; ok {
				p.results[peer].HTTP = resp
			} else {
				scopedLog.Debug("Node disappeared before result written")
			}
			p.Unlock()
		}
	}
}

func (p *prober) runICMPPinger() {
	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	debugLogsEnabled := logging.CanLogAt(log.Logger, logrus.DebugLevel)

	for name, ips := range p.getIPsByNode() {
		scopedLog := log

		if debugLogsEnabled {
			scopedLog = log.WithField(logfields.NodeName, name)
		}

		for _, ip := range ips {
			if debugLogsEnabled {
				scopedLog = scopedLog.WithFields(logrus.Fields{
					logfields.IPAddr: ip.String(),
				})
			}

			resp := p.icmpPing(name, ip.String())
			if resp.Status != "" {
				scopedLog.Debugf("Failed to probe: %s", resp.Status)
			}

			peer := ipString(ip.String())
			p.Lock()
			if _, ok := p.results[peer]; ok {
				p.results[peer].Icmp = resp
			} else {
				scopedLog.Debug("Node disappeared before result written")
			}
			p.Unlock()
		}
	}
}

// Run sends a single probes out to all of the other cilium nodes to gather
// connectivity status for the cluster.
func (p *prober) Run() {
	p.runHTTPProbe()
	p.runICMPPinger()
}

// Stop disrupts the currently running RunLoop(). This may only be called after
// a call to RunLoop().
func (p *prober) Stop() {
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
	go func() {
		tick := time.NewTicker(p.server.ProbeInterval)
		p.runHTTPProbe()
		p.runICMPPinger()
	loop:
		for {
			select {
			case <-p.stop:
				break loop
			case <-tick.C:
				// (1) We can receive the same nodes multiple times,
				// updated node is present in both nodesAdded and nodesRemoved
				// (2) We don't want to report stale nodes in metrics
				if nodesAdded, nodesRemoved, err := p.server.getNodes(); err != nil {
					// reset the cache by setting clientID to 0 and removing all current nodes
					p.server.clientID = 0
					p.setNodes(nil, p.nodes)
					log.WithError(err).Error("unable to get cluster nodes")
				} else {
					// (1) setNodes implementation doesn't override results for existing nodes.
					// (2) Remove stale nodes so we don't report them in metrics before updating results
					p.setNodes(nodesAdded, nodesRemoved)
					// (2) Update results without stale nodes
					p.server.updateCluster(p.getResults())
				}
				p.runHTTPProbe()
				p.runICMPPinger()
				continue
			}
		}
		tick.Stop()
		close(p.proberExited)
	}()
}

// newProber prepares a prober. The caller may invoke one the Run* methods of
// the prober to populate its 'results' map.
func newProber(s *Server, nodes nodeMap) *prober {
	prober := &prober{
		server:       s,
		proberExited: make(chan bool),
		stop:         make(chan bool),
		results:      make(map[ipString]*models.PathStatus),
		nodes:        make(nodeMap),
	}
	prober.setNodes(nodes, nil)
	return prober
}
