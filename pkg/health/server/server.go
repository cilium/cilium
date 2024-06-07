// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"fmt"
	"path"
	"time"

	"github.com/cilium/cilium/api/v1/client/daemon"
	healthModels "github.com/cilium/cilium/api/v1/health/models"
	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/health/server/restapi"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	ciliumPkg "github.com/cilium/cilium/pkg/client"
	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	healthClientPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/health/probe/responder"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "health-server")
)

// Config stores the configuration data for a cilium-health server.
type Config struct {
	Debug         bool
	CiliumURI     string
	ProbeInterval time.Duration
	ProbeDeadline time.Duration
	HTTPPathPort  int
	HealthAPISpec *healthApi.Spec
}

// ipString is an IP address used as a more descriptive type name in maps.
type ipString string

// nodeMap maps IP addresses to healthNode objects for convenient access to
// node information.
type nodeMap map[ipString]healthNode

// Server is the cilium-health daemon that is in charge of performing health
// and connectivity checks periodically, and serving the cilium-health API.
type Server struct {
	healthApi.Server  // Server to provide cilium-health API
	*ciliumPkg.Client // Client to "GET /healthz" on cilium daemon
	Config
	// clientID is the client ID returned by the cilium-agent that should
	// be used when making frequent requests. The server will return
	// a diff of the nodes added and removed based on this clientID.
	clientID int64

	httpPathServer *responder.Server // HTTP server for external pings
	startTime      time.Time

	// The lock protects against read and write access to the IP->Node map,
	// the list of statuses as most recently seen, and the last time a
	// probe was conducted.
	lock.RWMutex
	connectivity *healthReport
	localStatus  *healthModels.SelfStatus
}

const (
	probeTimeout = 60
)

// DumpUptime returns the time that this server has been running.
func (s *Server) DumpUptime() string {
	return time.Since(s.startTime).String()
}

// getNodes fetches the nodes added and removed from the last time the server
// made a request to the daemon.
func (s *Server) getNodes() (nodeMap, nodeMap, error) {
	scopedLog := log
	if s.CiliumURI != "" {
		scopedLog = log.WithField("URI", s.CiliumURI)
	}
	scopedLog.Debug("Sending request for /cluster/nodes ...")

	clusterNodesParam := daemon.NewGetClusterNodesParams()
	s.RWMutex.RLock()
	cID := s.clientID
	s.RWMutex.RUnlock()
	clusterNodesParam.SetClientID(&cID)
	resp, err := s.Daemon.GetClusterNodes(clusterNodesParam)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get nodes' cluster: %w", err)
	}
	log.Debug("Got cilium /cluster/nodes")

	if resp == nil || resp.Payload == nil {
		return nil, nil, fmt.Errorf("received nil health response")
	}

	s.RWMutex.Lock()
	s.clientID = resp.Payload.ClientID

	if resp.Payload.Self != "" {
		s.localStatus = &healthModels.SelfStatus{
			Name: resp.Payload.Self,
		}
	}
	s.RWMutex.Unlock()

	nodesAdded := nodeElementSliceToNodeMap(resp.Payload.NodesAdded)
	nodesRemoved := nodeElementSliceToNodeMap(resp.Payload.NodesRemoved)

	return nodesAdded, nodesRemoved, nil
}

// getAllNodes fetches all nodes the daemon is aware of.
func (s *Server) getAllNodes() (nodeMap, error) {
	scopedLog := log
	if s.CiliumURI != "" {
		scopedLog = log.WithField("URI", s.CiliumURI)
	}
	scopedLog.Debug("Sending request for /cluster/nodes ...")

	resp, err := s.Daemon.GetClusterNodes(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to get nodes' cluster: %w", err)
	}
	log.Debug("Got cilium /cluster/nodes")

	if resp == nil || resp.Payload == nil {
		return nil, fmt.Errorf("received nil health response")
	}

	nodesAdded := nodeElementSliceToNodeMap(resp.Payload.NodesAdded)

	return nodesAdded, nil
}

// nodeElementSliceToNodeMap returns a slice of models.NodeElement into a
// nodeMap.
func nodeElementSliceToNodeMap(nodeElements []*models.NodeElement) nodeMap {
	nodes := make(nodeMap)
	for _, n := range nodeElements {
		if n.PrimaryAddress != nil {
			if n.PrimaryAddress.IPV4 != nil {
				nodes[ipString(n.PrimaryAddress.IPV4.IP)] = NewHealthNode(n)
			}
			if n.PrimaryAddress.IPV6 != nil {
				nodes[ipString(n.PrimaryAddress.IPV6.IP)] = NewHealthNode(n)
			}
		}
		for _, addr := range n.SecondaryAddresses {
			nodes[ipString(addr.IP)] = NewHealthNode(n)
		}
		if n.HealthEndpointAddress != nil {
			if n.HealthEndpointAddress.IPV4 != nil {
				nodes[ipString(n.HealthEndpointAddress.IPV4.IP)] = NewHealthNode(n)
			}
			if n.HealthEndpointAddress.IPV6 != nil {
				nodes[ipString(n.HealthEndpointAddress.IPV6.IP)] = NewHealthNode(n)
			}
		}
	}
	return nodes
}

// updateCluster makes the specified health report visible to the API.
//
// It only updates the server's API-visible health report if the provided
// report started after the current report.
func (s *Server) updateCluster(report *healthReport) {
	s.Lock()
	defer s.Unlock()

	if s.connectivity.startTime.Before(report.startTime) {
		s.connectivity = report
		s.collectNodeConnectivityMetrics()
	}
}

func (s *Server) collectNodeConnectivityMetrics() {
	if s.localStatus == nil || s.connectivity == nil {
		return
	}
	localClusterName, localNodeName := getClusterNodeName(s.localStatus.Name)

	endpointStatuses := make(map[healthClientPkg.ConnectivityStatusType]int)
	nodeStatuses := make(map[healthClientPkg.ConnectivityStatusType]int)

	for _, n := range s.connectivity.nodes {
		if n == nil || n.Host == nil || n.Host.PrimaryAddress == nil || n.HealthEndpoint == nil || n.HealthEndpoint.PrimaryAddress == nil {
			continue
		}

		targetClusterName, targetNodeName := getClusterNodeName(n.Name)
		nodePathPrimaryAddress := healthClientPkg.GetHostPrimaryAddress(n)
		nodePathSecondaryAddress := healthClientPkg.GetHostSecondaryAddresses(n)

		endpointPathStatus := n.HealthEndpoint

		isEndpointReachable := healthClientPkg.SummarizePathConnectivityStatus(healthClientPkg.GetAllEndpointAddresses(n)) == healthClientPkg.ConnStatusReachable
		isNodeReachable := healthClientPkg.SummarizePathConnectivityStatus(healthClientPkg.GetAllHostAddresses(n)) == healthClientPkg.ConnStatusReachable

		isHealthEndpointReachable := healthClientPkg.SummarizePathConnectivityStatusType(healthClientPkg.GetAllEndpointAddresses(n))
		isHealthNodeReachable := healthClientPkg.SummarizePathConnectivityStatusType(healthClientPkg.GetAllHostAddresses(n))

		location := metrics.LabelLocationLocalNode
		if targetClusterName != localClusterName {
			location = metrics.LabelLocationRemoteInterCluster
		} else if targetNodeName != localNodeName {
			location = metrics.LabelLocationRemoteIntraCluster
		}

		// Aggregated status for endpoint connectivity
		metrics.NodeConnectivityStatus.WithLabelValues(
			localClusterName, localNodeName, targetClusterName, targetNodeName, location, metrics.LabelPeerEndpoint).
			Set(metrics.BoolToFloat64(isEndpointReachable))

		// Aggregated status for node connectivity
		metrics.NodeConnectivityStatus.WithLabelValues(
			localClusterName, localNodeName, targetClusterName, targetNodeName, location, metrics.LabelPeerNode).
			Set(metrics.BoolToFloat64(isNodeReachable))

		// Aggregate health connectivity statuses
		for connectivityStatusType, value := range isHealthEndpointReachable {
			endpointStatuses[connectivityStatusType] += value
		}
		for connectivityStatusType, value := range isHealthNodeReachable {
			nodeStatuses[connectivityStatusType] += value
		}

		// HTTP endpoint primary
		collectConnectivityMetric(endpointPathStatus.PrimaryAddress.HTTP, localClusterName, localNodeName,
			targetClusterName, targetNodeName, endpointPathStatus.PrimaryAddress.IP,
			location, metrics.LabelPeerEndpoint, metrics.LabelTrafficHTTP, metrics.LabelAddressTypePrimary)

		// HTTP endpoint secondary
		for _, secondary := range endpointPathStatus.SecondaryAddresses {
			collectConnectivityMetric(secondary.HTTP, localClusterName, localNodeName,
				targetClusterName, targetNodeName, secondary.IP,
				location, metrics.LabelPeerEndpoint, metrics.LabelTrafficHTTP, metrics.LabelAddressTypeSecondary)
		}

		// HTTP node primary
		collectConnectivityMetric(nodePathPrimaryAddress.HTTP, localClusterName, localNodeName,
			targetClusterName, targetNodeName, nodePathPrimaryAddress.IP,
			location, metrics.LabelPeerNode, metrics.LabelTrafficHTTP, metrics.LabelAddressTypePrimary)

		// HTTP node secondary
		for _, secondary := range nodePathSecondaryAddress {
			collectConnectivityMetric(secondary.HTTP, localClusterName, localNodeName,
				targetClusterName, targetNodeName, secondary.IP,
				location, metrics.LabelPeerNode, metrics.LabelTrafficHTTP, metrics.LabelAddressTypeSecondary)
		}

		// ICMP endpoint primary
		collectConnectivityMetric(endpointPathStatus.PrimaryAddress.Icmp, localClusterName, localNodeName,
			targetClusterName, targetNodeName, endpointPathStatus.PrimaryAddress.IP,
			location, metrics.LabelPeerEndpoint, metrics.LabelTrafficICMP, metrics.LabelAddressTypePrimary)

		// ICMP endpoint secondary
		for _, secondary := range endpointPathStatus.SecondaryAddresses {
			collectConnectivityMetric(secondary.Icmp, localClusterName, localNodeName,
				targetClusterName, targetNodeName, secondary.IP,
				location, metrics.LabelPeerEndpoint, metrics.LabelTrafficICMP, metrics.LabelAddressTypeSecondary)
		}

		// ICMP node primary
		collectConnectivityMetric(nodePathPrimaryAddress.Icmp, localClusterName, localNodeName,
			targetClusterName, targetNodeName, nodePathPrimaryAddress.IP,
			location, metrics.LabelPeerNode, metrics.LabelTrafficICMP, metrics.LabelAddressTypePrimary)

		// ICMP node secondary
		for _, secondary := range nodePathSecondaryAddress {
			collectConnectivityMetric(secondary.Icmp, localClusterName, localNodeName,
				targetClusterName, targetNodeName, secondary.IP,
				location, metrics.LabelPeerNode, metrics.LabelTrafficICMP, metrics.LabelAddressTypeSecondary)
		}
	}

	// Aggregated health statuses for endpoint connectivity
	metrics.NodeHealthConnectivityStatus.WithLabelValues(
		localClusterName, localNodeName, metrics.LabelPeerEndpoint, metrics.LabelReachable).
		Set(float64(endpointStatuses[healthClientPkg.ConnStatusReachable]))

	metrics.NodeHealthConnectivityStatus.WithLabelValues(
		localClusterName, localNodeName, metrics.LabelPeerEndpoint, metrics.LabelUnreachable).
		Set(float64(endpointStatuses[healthClientPkg.ConnStatusUnreachable]))

	metrics.NodeHealthConnectivityStatus.WithLabelValues(
		localClusterName, localNodeName, metrics.LabelPeerEndpoint, metrics.LabelUnknown).
		Set(float64(endpointStatuses[healthClientPkg.ConnStatusUnknown]))

	// Aggregated health statuses for node connectivity
	metrics.NodeHealthConnectivityStatus.WithLabelValues(
		localClusterName, localNodeName, metrics.LabelPeerNode, metrics.LabelReachable).
		Set(float64(nodeStatuses[healthClientPkg.ConnStatusReachable]))

	metrics.NodeHealthConnectivityStatus.WithLabelValues(
		localClusterName, localNodeName, metrics.LabelPeerNode, metrics.LabelUnreachable).
		Set(float64(nodeStatuses[healthClientPkg.ConnStatusUnreachable]))

	metrics.NodeHealthConnectivityStatus.WithLabelValues(
		localClusterName, localNodeName, metrics.LabelPeerNode, metrics.LabelUnknown).
		Set(float64(nodeStatuses[healthClientPkg.ConnStatusUnknown]))
}

func collectConnectivityMetric(status *healthModels.ConnectivityStatus, labels ...string) {
	// collect deprecated node_connectivity_latency_seconds
	var metricValue float64 = -1
	if status != nil {
		metricValue = float64(status.Latency) / float64(time.Second)
	}
	metrics.NodeConnectivityLatency.WithLabelValues(labels...).Set(metricValue)

	// collect node_health_connectivity_latency_seconds
	if status != nil {
		// node_health_connectivity_latency_seconds copies a subset of the labels
		// of the deprecated metric for use when observing metrics
		if len(labels) < 7 {
			log.Warn("node_health_connectivity_latency_seconds metric is missing labels, could not be collected")
			return
		}
		healthLabels := make([]string, 5)
		copy(healthLabels, labels[0:2])
		copy(healthLabels[2:], labels[6:])
		if status.Status == "" {
			metricValue = float64(status.Latency) / float64(time.Second)
			metrics.NodeHealthConnectivityLatency.WithLabelValues(healthLabels...).Observe(metricValue)
		} else {
			metrics.NodeHealthConnectivityLatency.WithLabelValues(healthLabels...).Observe(probeTimeout)
		}
	}
}

// getClusterNodeName returns the cluster name and node name if possible.
func getClusterNodeName(str string) (string, string) {
	clusterName, nodeName := path.Split(str)
	if len(clusterName) == 0 {
		return ciliumDefaults.ClusterName, nodeName
	}
	// remove forward slash at the end if any for cluster name
	return path.Dir(clusterName), nodeName
}

// GetStatusResponse returns the most recent cluster connectivity status.
func (s *Server) GetStatusResponse() *healthModels.HealthStatusResponse {
	s.RLock()
	defer s.RUnlock()

	var name string
	// Check if localStatus is populated already. If not, the name is empty
	if s.localStatus != nil {
		name = s.localStatus.Name
	}

	return &healthModels.HealthStatusResponse{
		Local: &healthModels.SelfStatus{
			Name: name,
		},
		Nodes:     s.connectivity.nodes,
		Timestamp: s.connectivity.startTime.Format(time.RFC3339),
	}
}

// FetchStatusResponse updates the cluster with the latest set of nodes,
// runs a synchronous probe across the cluster, updates the connectivity cache
// and returns the results.
func (s *Server) FetchStatusResponse() (*healthModels.HealthStatusResponse, error) {
	nodes, err := s.getAllNodes()
	if err != nil {
		return nil, err
	}

	prober := newProber(s, nodes)
	if err := prober.Run(); err != nil {
		log.WithError(err).Info("Failed to run ping")
		return nil, err
	}
	log.Debug("Run complete")
	s.updateCluster(prober.getResults())

	return s.GetStatusResponse(), nil
}

// Run services that are actively probing other hosts and endpoints over
// ICMP and HTTP, and hosting the health admin API on a local Unix socket.
// Blocks indefinitely, or returns any errors that occur hosting the Unix
// socket API server.
func (s *Server) runActiveServices() error {
	// Run it once at the start so we get some initial status
	s.FetchStatusResponse()

	// We can safely ignore nodesRemoved since it's the first time we are
	// fetching the nodes from the server.
	nodesAdded, _, _ := s.getNodes()
	prober := newProber(s, nodesAdded)
	prober.MaxRTT = s.ProbeInterval
	prober.OnIdle = func() {
		// OnIdle is called every ProbeInterval after sending out all icmp pings.
		// There are a few important consideration here:
		// (1) ICMP prober doesn't report failed probes
		// (2) We can receive the same nodes multiple times,
		// updated node is present in both nodesAdded and nodesRemoved
		// (3) We need to clean icmp status to not retain stale probe results
		// (4) We don't want to report stale nodes in metrics

		if nodesAdded, nodesRemoved, err := s.getNodes(); err != nil {
			// reset the cache by setting clientID to 0 and removing all current nodes
			s.clientID = 0
			prober.setNodes(nil, prober.nodes)
			log.WithError(err).Error("unable to get cluster nodes")
			return
		} else {
			// (1) Mark ips that did not receive ICMP as unreachable.
			prober.updateIcmpStatus()
			// (2) setNodes implementation doesn't override results for existing nodes.
			// (4) Remove stale nodes so we don't report them in metrics before updating results
			prober.setNodes(nodesAdded, nodesRemoved)
			// (4) Update results without stale nodes
			s.updateCluster(prober.getResults())
			// (3) Cleanup icmp results for next iteration of probing
			prober.clearIcmpStatus()
		}
	}
	prober.RunLoop()
	defer prober.Stop()

	return s.Server.Serve()
}

// Serve spins up the following goroutines:
//   - HTTP API Server: Responder to the health API "/hello" message
//   - Prober: Periodically run pings across the cluster at a configured interval
//     and update the server's connectivity status cache.
//   - Unix API Server: Handle all health API requests over a unix socket.
//
// Callers should first defer the Server.Shutdown(), then call Serve().
func (s *Server) Serve() (err error) {
	errors := make(chan error)

	go func() {
		errors <- s.httpPathServer.Serve()
	}()

	go func() {
		errors <- s.runActiveServices()
	}()

	// Block for the first error, then return.
	err = <-errors
	return err
}

// Shutdown server and clean up resources
func (s *Server) Shutdown() {
	s.httpPathServer.Shutdown()
	s.Server.Shutdown()
}

// newServer instantiates a new instance of the health API server on the
// defaults unix socket.
func (s *Server) newServer(spec *healthApi.Spec) *healthApi.Server {
	restAPI := restapi.NewCiliumHealthAPIAPI(spec.Document)
	restAPI.Logger = log.Printf

	// Admin API
	restAPI.GetHealthzHandler = NewGetHealthzHandler(s)
	restAPI.ConnectivityGetStatusHandler = NewGetStatusHandler(s)
	restAPI.ConnectivityPutStatusProbeHandler = NewPutStatusProbeHandler(s)

	api.DisableAPIs(spec.DeniedAPIs, restAPI.AddMiddlewareFor)
	srv := healthApi.NewServer(restAPI)
	srv.EnabledListeners = []string{"unix"}
	srv.SocketPath = defaults.SockPath

	srv.ConfigureAPI()

	return srv
}

// NewServer creates a server to handle health requests.
func NewServer(config Config) (*Server, error) {
	server := &Server{
		startTime:    time.Now(),
		Config:       config,
		connectivity: &healthReport{},
	}

	cl, err := ciliumPkg.NewClient(config.CiliumURI)
	if err != nil {
		return nil, err
	}

	server.Client = cl
	server.Server = *server.newServer(config.HealthAPISpec)

	server.httpPathServer = responder.NewServers(getAddresses(), config.HTTPPathPort)

	return server, nil
}

// Get internal node ipv4/ipv6 addresses based on config enabled.
// If it fails to get either of internal node address, it returns "0.0.0.0" if ipv4 or "::" if ipv6.
func getAddresses() []string {
	addresses := make([]string, 0, 2)

	// listen on all interfaces and all families in case of external-workloads
	if option.Config.JoinCluster {
		return []string{""}
	}

	if option.Config.EnableIPv4 {
		if ipv4 := node.GetInternalIPv4(); ipv4 != nil {
			addresses = append(addresses, ipv4.String())
		} else {
			// if Get ipv4 fails, then listen on all ipv4 addr.
			addresses = append(addresses, "0.0.0.0")
		}
	}

	if option.Config.EnableIPv6 {
		if ipv6 := node.GetInternalIPv6(); ipv6 != nil {
			addresses = append(addresses, ipv6.String())
		} else {
			// if Get ipv6 fails, then listen on all ipv6 addr.
			addresses = append(addresses, "::")
		}
	}

	return addresses
}
