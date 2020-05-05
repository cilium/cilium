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

package server

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/client/daemon"
	healthModels "github.com/cilium/cilium/api/v1/health/models"
	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/health/server/restapi"
	"github.com/cilium/cilium/api/v1/models"
	ciliumPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/health/probe/responder"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/go-openapi/loads"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "health-server")

	// PortToPaths is a convenience map for access to the ports and their
	// common string representations
	PortToPaths = map[int]string{
		defaults.HTTPPathPort: "Via L3",
	}
)

// Config stores the configuration data for a cilium-health server.
type Config struct {
	Debug         bool
	CiliumURI     string
	ProbeInterval time.Duration
	ProbeDeadline time.Duration
}

// ipString is an IP address used as a more descriptive type name in maps.
type ipString string

// nodeMap maps IP addresses to healthNode objectss for convenient access to
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

	tcpServers []*responder.Server // Servers for external pings
	startTime  time.Time

	// The lock protects against read and write access to the IP->Node map,
	// the list of statuses as most recently seen, and the last time a
	// probe was conducted.
	lock.RWMutex
	connectivity *healthReport
	localStatus  *healthModels.SelfStatus
}

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
		return nil, nil, fmt.Errorf("unable to get nodes' cluster: %s", err)
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
		return nil, fmt.Errorf("unable to get nodes' cluster: %s", err)
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
	}
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
		// Fetch results and update set of nodes to probe every
		// ProbeInterval
		s.updateCluster(prober.getResults())
		if nodesAdded, nodesRemoved, err := s.getNodes(); err != nil {
			log.WithError(err).Error("unable to get cluster nodes")
		} else {
			prober.setNodes(nodesAdded, nodesRemoved)
		}
	}
	prober.RunLoop()
	defer prober.Stop()

	return s.Server.Serve()
}

// Serve spins up the following goroutines:
// * TCP API Server: Responders to the health API "/hello" message, one per path
// * Prober: Periodically run pings across the cluster at a configured interval
//   and update the server's connectivity status cache.
// * Unix API Server: Handle all health API requests over a unix socket.
//
// Callers should first defer the Server.Shutdown(), then call Serve().
func (s *Server) Serve() (err error) {
	errors := make(chan error)

	for i := range s.tcpServers {
		srv := s.tcpServers[i]
		go func() {
			errors <- srv.Serve()
		}()
	}

	go func() {
		errors <- s.runActiveServices()
	}()

	// Block for the first error, then return.
	err = <-errors
	return err
}

// Shutdown server and clean up resources
func (s *Server) Shutdown() {
	for i := range s.tcpServers {
		s.tcpServers[i].Shutdown()
	}
	s.Server.Shutdown()
}

// newServer instantiates a new instance of the health API server on the
// defaults unix socket.
func (s *Server) newServer(spec *loads.Document) *healthApi.Server {
	api := restapi.NewCiliumHealthAPI(spec)
	api.Logger = log.Printf

	// Admin API
	api.GetHealthzHandler = NewGetHealthzHandler(s)
	api.ConnectivityGetStatusHandler = NewGetStatusHandler(s)
	api.ConnectivityPutStatusProbeHandler = NewPutStatusProbeHandler(s)

	srv := healthApi.NewServer(api)
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
		tcpServers:   []*responder.Server{},
		connectivity: &healthReport{},
	}

	swaggerSpec, err := loads.Analyzed(healthApi.SwaggerJSON, "")
	if err != nil {
		return nil, err
	}

	cl, err := ciliumPkg.NewClient(config.CiliumURI)
	if err != nil {
		return nil, err
	}

	server.Client = cl
	server.Server = *server.newServer(swaggerSpec)

	for port := range PortToPaths {
		srv := responder.NewServer(port)
		server.tcpServers = append(server.tcpServers, srv)
	}

	return server, nil
}
