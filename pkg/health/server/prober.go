// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/health/models"
	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/health/probe"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// healthReport is a snapshot of the health of the cluster.
type healthReport struct {
	startTime     time.Time
	nodes         []*models.NodeStatus
	probeInterval time.Duration
}

type connectivityResult struct {
	ip     netip.Addr
	status *models.ConnectivityStatus
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
	results map[netip.Addr]*models.PathStatus
	nodes   nodeMap

	probeRateLimiter *rate.Limiter
	probeInterval    time.Duration
	probeIpCount     int
}

// copyResultRLocked makes a copy of the path status for the specified IP.
func (p *prober) copyResultRLocked(ip netip.Addr) *models.PathStatus {
	status := p.results[ip]
	if status == nil {
		return nil
	}

	result := &models.PathStatus{
		IP: ip.String(),
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

		if primaryHealthIP.IsValid() {
			primaryEndpointAddress := p.copyResultRLocked(primaryHealthIP)
			status.Endpoint = primaryEndpointAddress
			status.HealthEndpoint = &models.EndpointStatus{
				PrimaryAddress:     primaryEndpointAddress,
				SecondaryAddresses: secondaryEndpointAddresses,
			}
		}

		resultMap[node.Name] = status
	}

	result := &healthReport{startTime: p.start, probeInterval: p.probeInterval}
	for _, res := range resultMap {
		result.nodes = append(result.nodes, res)
	}
	return result
}

func skipAddress(elem *ciliumModels.NodeAddressingElement) bool {
	return elem == nil || !elem.Enabled || !elem.IP.IsValid()
}

// probeAddr returns the IP address specified in the addressing element, or
// the zero netip.Addr if this IP should not be pinged.
func probeAddr(logger *slog.Logger, n *healthNode, addr *ciliumModels.NodeAddressingElement, primary bool) netip.Addr {
	node := n.NodeElement

	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	scopedLog := logger
	if scopedLog.Enabled(context.Background(), slog.LevelDebug) {
		scopedLog = scopedLog.With(
			logfields.NodeName, node.Name,
			logfields.IPAddr, addr.IP,
			logfields.Primary, primary,
		)
	}

	if skipAddress(addr) {
		scopedLog.Debug("Skipping probe for address")
		return netip.Addr{}
	}

	scopedLog.Debug("Probing for connectivity to node")
	return addr.IP.Addr
}

// RemoveIP removes all traces of the specified IP from the prober, including
// clearing all cached results, mapping from this IP to a node, and entries in
// the ICMP and TCP pingers.
func (p *prober) RemoveIP(ip netip.Addr) {
	delete(p.results, ip)
	delete(p.nodes, ip)
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
	readdedIPs := sets.New[netip.Addr]()
	for _, n := range added {
		for elem, primary := range n.Addresses() {
			ip := probeAddr(p.server.logger, &n, elem, primary)
			if !ip.IsValid() {
				continue
			}
			readdedIPs.Insert(ip)
		}
	}

	for _, n := range removed {
		for elem := range n.Addresses() {
			ip := elem.IP.Addr
			if !readdedIPs.Has(ip) {
				p.RemoveIP(ip)
			}
		}
	}

	for _, n := range added {
		for elem, primary := range n.Addresses() {
			ip := probeAddr(p.server.logger, &n, elem, primary)
			if !ip.IsValid() {
				continue
			}

			p.nodes[ip] = n

			if p.results[ip] == nil {
				p.results[ip] = &models.PathStatus{
					IP: ip.String(),
				}
			}
		}
	}
}

const httpPathDescription = "Via L3"

func (p *prober) getIPsByNode() map[string][]netip.Addr {
	p.RLock()
	defer p.RUnlock()

	// p.nodes is mapped from all known IPs -> nodes in N:M configuration,
	// so multiple IPs could refer to the same node. To ensure we only
	// ping each node once, deduplicate nodes into map of nodeName -> []IP.
	nodes := make(map[string][]netip.Addr)
	for _, node := range p.nodes {
		if nodes[node.Name] != nil {
			// Already handled this node.
			continue
		}
		nodes[node.Name] = []netip.Addr{}
		for elem, primary := range node.Addresses() {
			if ip := probeAddr(p.server.logger, &node, elem, primary); ip.IsValid() {
				nodes[node.Name] = append(nodes[node.Name], ip)
			}
		}
	}

	return nodes
}

func icmpPing(logger *slog.Logger, node string, ip netip.Addr, ctx context.Context, resChan chan<- connectivityResult, wg *sync.WaitGroup, probeDeadline time.Duration, nReqs int) {
	defer wg.Done()

	result := &models.ConnectivityStatus{}

	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	debugLogsEnabled := logger.Enabled(context.Background(), slog.LevelDebug)
	scopedLog := logger
	if debugLogsEnabled {
		scopedLog = scopedLog.With(
			logfields.NodeName, node,
			logfields.IPAddr, ip,
		)
		scopedLog.Debug("Pinging host")
	}

	pinger, err := probing.NewPinger(ip.String())
	if err != nil {
		scopedLog.Debug("Failed to create pinger", logfields.Error, err)
		result.Status = err.Error()
		resChan <- connectivityResult{ip: ip, status: result}
		return
	}

	pinger.Timeout = probeDeadline
	pinger.Count = nReqs
	pinger.Interval = 100 * time.Millisecond
	pinger.OnRecv = func(pkt *probing.Packet) {
		// As we already received response,
		// no need to send out more pings.
		pinger.Stop()
	}
	pinger.OnFinish = func(stats *probing.Statistics) {
		if stats.PacketsRecv > 0 && len(stats.Rtts) > 0 {
			if debugLogsEnabled {
				scopedLog.Debug("Ping successful", logfields.RTT, stats.Rtts[0])
			}
			result.Latency = stats.Rtts[0].Nanoseconds()
		} else {
			scopedLog.Debug("Ping failed")
			result.Status = "Connection timed out"
		}
		result.LastProbed = time.Now().Format(time.RFC3339)
	}
	pinger.SetPrivileged(true)
	err = pinger.RunWithContext(ctx)
	if err != nil {
		scopedLog.Debug(
			"Failed to run pinger for IP",
			logfields.Error, err,
		)
		result.Status = err.Error()
	}
	resChan <- connectivityResult{ip: ip, status: result}
}

func per(nodes int, duration time.Duration) rate.Limit {
	if nodes == 0 {
		nodes = 1
	}
	return rate.Every(duration / time.Duration(nodes))
}

func httpProbe(logger *slog.Logger, node string, ip netip.Addr, ctx context.Context, resChan chan<- connectivityResult, wg *sync.WaitGroup, httpPort int) {
	defer wg.Done()

	result := &models.ConnectivityStatus{}
	host := "http://" + netip.AddrPortFrom(ip, uint16(httpPort)).String()
	// Only add fields to the scoped logger if debug is enabled, to save on resources.
	// This can be done since all logs in this function are debug-level only.
	debugLogsEnabled := logger.Enabled(context.Background(), slog.LevelDebug)
	scopedLog := logger
	if debugLogsEnabled {
		scopedLog = logger.With(
			logfields.NodeName, node,
			logfields.IPAddr, ip,
			logfields.HostIP, host,
			logfields.Route, httpPathDescription,
		)
		scopedLog.Debug("Greeting host")
	}

	start := time.Now()
	err := probe.GetHello(host)
	rtt := time.Since(start)
	if err == nil {
		if debugLogsEnabled {
			scopedLog.Debug("Greeting successful", logfields.RTT, rtt)
		}
		result.Latency = rtt.Nanoseconds()
	} else {
		if debugLogsEnabled {
			scopedLog.Debug("Greeting failed", logfields.Error, err)
		}
		result.Status = err.Error()
	}
	result.LastProbed = time.Now().Format(time.RFC3339)

	resChan <- connectivityResult{ip: ip, status: result}
}

func (p *prober) runProbe(nodeIps map[string][]netip.Addr) {
	httpResChan := make(chan connectivityResult)
	icmpResChan := make(chan connectivityResult)
	wg := sync.WaitGroup{}
	resultsWg := sync.WaitGroup{}

	startTime := time.Now()
	p.Lock()
	p.start = startTime
	p.Unlock()

	p.probeRateLimiter = rate.NewLimiter(per(p.probeIpCount, p.probeInterval), 1)

	// update results as probes complete
	resultsWg.Add(2)
	go func() {
		defer resultsWg.Done()
		for resp := range httpResChan {
			p.Lock()
			if _, ok := p.results[resp.ip]; ok {
				p.results[resp.ip].HTTP = resp.status
			} else {
				p.server.logger.Debug("Node disappeared before result written")
			}
			p.Unlock()
		}
	}()

	go func() {
		defer resultsWg.Done()
		for resp := range icmpResChan {
			p.Lock()
			if _, ok := p.results[resp.ip]; ok {
				p.results[resp.ip].Icmp = resp.status
			} else {
				p.server.logger.Debug("Node disappeared before result written")
			}
			p.Unlock()
		}
	}()

	for name, ips := range nodeIps {
		for _, ip := range ips {
			ctx := context.Background()
			if err := p.probeRateLimiter.Wait(ctx); err != nil {
				result := &models.ConnectivityStatus{}
				result.Status = err.Error()
				httpResChan <- connectivityResult{ip: ip, status: result}
				icmpResChan <- connectivityResult{ip: ip, status: result}
			} else {
				wg.Add(2)
				go httpProbe(p.server.logger, name, ip, ctx, httpResChan, &wg, p.server.Config.HTTPPathPort)
				go icmpPing(p.server.logger, name, ip, ctx, icmpResChan, &wg, p.server.Config.ProbeDeadline, p.server.Config.ICMPReqsCount)
			}
		}
	}

	// owner closes result channels only once all probe results have been written
	go func() {
		wg.Wait()
		close(httpResChan)
		close(icmpResChan)
	}()

	// block until all results are written
	resultsWg.Wait()
}

// Stop disrupts the currently running RunLoop(). This may only be called after
// a call to RunLoop().
func (p *prober) Stop() {
	close(p.stop)
	<-p.proberExited
}

// RunLoop periodically sends probes out to all of the other cilium nodes to
// gather connectivity status for the cluster once the current probing interval
// has elapsed.
//
// This is a non-blocking method so it immediately returns. If you want to
// stop sending packets, call Stop().
func (p *prober) RunLoop() {
	go func() {
		nodeIps := p.getIPsByNode()
		p.setProbeInterval(nodeIps)
		tick := time.NewTicker(p.probeInterval)
		p.runProbe(nodeIps)
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
					p.server.logger.Error("unable to get cluster nodes", logfields.Error, err)
				} else {
					// (1) setNodes implementation doesn't override results for existing nodes.
					// (2) Remove stale nodes so we don't report them in metrics before updating results
					p.setNodes(nodesAdded, nodesRemoved)
					// (2) Update results without stale nodes
					p.server.updateCluster(p.getResults())
				}
				// Reset probe interval based on cluster size.
				nodeIps := p.getIPsByNode()
				changedInterval := p.setProbeInterval(nodeIps)
				if changedInterval {
					tick.Reset(p.probeInterval)
				}
				p.runProbe(nodeIps)
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
	s.logger.Debug("Creating new prober")

	prober := &prober{
		server:       s,
		proberExited: make(chan bool),
		stop:         make(chan bool),
		results:      make(map[netip.Addr]*models.PathStatus),
		nodes:        make(nodeMap),
	}
	prober.setNodes(nodes, nil)
	return prober
}

// Given user-provided ConnectivityProbeFrequencyRatio, uses base interval
// in [10, 110] to set the probe interval, where base interval is 10 + ratio * 100.
// Returns true if the interval has changed.
func (p *prober) setProbeInterval(nodeIps map[string][]netip.Addr) bool {
	baseInterval := (10 + option.Config.ConnectivityProbeFrequencyRatio*100) * 1e9
	ipCount := 0
	for _, ips := range nodeIps {
		ipCount += len(ips)
	}
	p.Lock()
	defer p.Unlock()
	oldInterval := p.probeInterval
	p.probeInterval = backoff.ClusterSizeDependantInterval(time.Duration(baseInterval), ipCount)
	p.probeIpCount = ipCount
	p.server.logger.Debug(
		"Setting probe interval for IPs",
		logfields.Interval, p.probeInterval,
		logfields.LenIPs, p.probeIpCount,
	)
	return oldInterval != p.probeInterval
}
