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
	"sync"
	"time"

	healthModels "github.com/cilium/cilium/api/v1/health/models"
	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/health/server/restapi"
	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	ciliumPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/go-openapi/loads"
	flags "github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
)

// AdminOption is an option for determining over which protocols the APIs are
// exposed.
type AdminOption string

const (
	// AdminOptionAny exposes every API over both Unix and HTTP sockets.
	AdminOptionAny AdminOption = "any"

	// AdminOptionUnix restricts most APIs to hosting over Unix sockets.
	AdminOptionUnix AdminOption = "unix"
)

var (
	log = common.DefaultLogger

	// PortToPaths is a convenience map for access to the ports and their
	// common string representations
	PortToPaths = map[int]string{
		defaults.HTTPPathPort: "Via L3",
	}

	// AdminOptions is the slice of all valid AdminOption values.
	AdminOptions = []AdminOption{
		AdminOptionAny,
		AdminOptionUnix,
	}
)

// Config stores the configuration data for a cilium-health server.
type Config struct {
	Debug         bool
	Passive       bool
	Admin         AdminOption
	CiliumURI     string
	ProbeInterval time.Duration
	ProbeDeadline time.Duration
}

// ipString is an IP address used as a more descriptive type name in maps.
type ipString string

// nodeMap maps IP addresses to NodeElements for convenient access to node
// information.
type nodeMap map[ipString]*ciliumModels.NodeElement

// Server is the cilium-health daemon that is in charge of performing health
// and connectivity checks periodically, and serving the cilium-health API.
type Server struct {
	healthApi.Server  // Server to provide cilium-health API
	*ciliumPkg.Client // Client to "GET /healthz" on cilium daemon
	Config

	waitgroup  sync.WaitGroup      // Used to synchronize all goroutines
	tcpServers []*healthApi.Server // Servers for external pings
	startTime  time.Time

	// The lock protects against read and write access to the IP->Node map,
	// the list of statuses as most recently seen, and the last time a
	// probe was conducted.
	lock.RWMutex
	connectivity []*healthModels.NodeStatus
	lastProbe    time.Time
	localStatus  *healthModels.SelfStatus
}

// DumpUptime returns the time that this server has been running.
func (s *Server) DumpUptime() string {
	return time.Since(s.startTime).String()
}

// getNodes fetches the latest set of nodes in the cluster from the Cilium
// daemon, and updates the Server's 'nodes' map.
func (s *Server) getNodes() (nodeMap, error) {
	scopedLog := logrus.NewEntry(log)
	if s.CiliumURI != "" {
		scopedLog = log.WithField("URI", s.CiliumURI)
	}
	scopedLog.Debug("Sending request for /healthz ...")

	resp, err := s.Daemon.GetHealthz(nil)
	if err != nil {
		log.WithError(err).Warn("Failed to retrieve Cilium /healthz")
		return nil, err
	}
	log.Debug("Got cilium /healthz")

	if resp.Payload.Cluster.Self != "" {
		s.localStatus = &healthModels.SelfStatus{
			Name: resp.Payload.Cluster.Self,
		}
	}

	nodes := make(nodeMap)
	for _, n := range resp.Payload.Cluster.Nodes {
		if n.PrimaryAddress.IPV4 != nil {
			nodes[ipString(n.PrimaryAddress.IPV4.IP)] = n
		}
		if n.PrimaryAddress.IPV6 != nil {
			nodes[ipString(n.PrimaryAddress.IPV6.IP)] = n
		}
		for _, addr := range n.SecondaryAddresses {
			nodes[ipString(addr.IP)] = n
		}
	}
	return nodes, nil
}

func (s *Server) updateCluster(connectivity []*healthModels.NodeStatus) {
	s.Lock()
	defer s.Unlock()

	s.lastProbe = time.Now()
	s.connectivity = connectivity
}

// GetStatusResponse returns the most recent cluster connectivity status.
func (s *Server) GetStatusResponse() *healthModels.HealthStatusResponse {
	s.RLock()
	defer s.RUnlock()
	return &healthModels.HealthStatusResponse{
		Local: &healthModels.SelfStatus{
			Name: s.localStatus.Name,
		},
		Nodes:     s.connectivity,
		Timestamp: s.lastProbe.Format(time.RFC3339),
	}
}

// FetchStatusResponse updates the cluster with the latest set of nodes,
// runs a synchronous probe across the cluster, updates the connectivity cache
// and returns the results.
func (s *Server) FetchStatusResponse() (*healthModels.HealthStatusResponse, error) {
	nodes, err := s.getNodes()
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

// Run services that are not considered 'Passive': Actively probing other
// hosts and endpoints over ICMP and HTTP, and hosting a local Unix socket.
// Blocks indefinitely, or returns any errors that occur hosting the Unix
// socket API server.
func (s *Server) runActiveServices() error {
	// Run it once at the start so we get some initial status
	s.FetchStatusResponse()

	nodes, _ := s.getNodes()
	prober := newProber(s, nodes)
	prober.MaxRTT = s.ProbeInterval
	prober.OnIdle = func() {
		// Fetch results and update set of nodes to probe every
		// ProbeInterval
		s.updateCluster(prober.getResults())
		if nodes, err := s.getNodes(); err == nil {
			prober.setNodes(nodes)
		}
	}
	prober.RunLoop()

	err := s.Server.Serve()
	prober.Stop()

	return err
}

// Serve spins up the following goroutines:
// * TCP API Server: Responders to the health API "/hello" message, one per path
//
// Also, if "Passive" is not set in s.Config:
// * Prober: Periodically run pings across the cluster at a configured interval
//   and update the server's connectivity status cache.
// * Unix API Server: Handle all health API requests over a unix socket.
func (s *Server) Serve() (err error) {
	for i := range s.tcpServers {
		s.waitgroup.Add(1)
		srv := s.tcpServers[i]
		go func() {
			defer s.waitgroup.Done()
			srv.Serve()
		}()
	}

	if !s.Config.Passive {
		err = s.runActiveServices()
	}
	s.waitgroup.Wait()

	return err
}

// Shutdown server and clean up resources
func (s *Server) Shutdown() {
	for i := range s.tcpServers {
		s.tcpServers[i].Shutdown()
	}
	if !s.Config.Passive {
		s.Server.Shutdown()
	}
}

func enableAPI(opt AdminOption, tcpPort int) bool {
	switch opt {
	case AdminOptionAny:
		return true
	case AdminOptionUnix:
		return tcpPort == 0
	default:
		return false
	}
}

// newServer instantiates a new instance of the API that serves the health
// API on the specified port. If tcpPort is 0, then a unix socket is opened
// which serves the entire API. If a tcpPort is specified, then it returns
// a server which only answers get requests for the root URL "/".
func (s *Server) newServer(spec *loads.Document, tcpPort int) *healthApi.Server {
	api := restapi.NewCiliumHealthAPI(spec)
	api.Logger = log.Printf

	// /hello
	api.GetHelloHandler = NewGetHelloHandler(s)

	if enableAPI(s.Config.Admin, tcpPort) {
		api.GetHealthzHandler = NewGetHealthzHandler(s)
		api.ConnectivityGetStatusHandler = NewGetStatusHandler(s)
		api.ConnectivityPutStatusProbeHandler = NewPutStatusProbeHandler(s)
	}

	srv := healthApi.NewServer(api)
	if tcpPort == 0 {
		srv.EnabledListeners = []string{"unix"}
		srv.SocketPath = flags.Filename(defaults.SockPath)
	} else {
		srv.EnabledListeners = []string{"http"}
		srv.Port = tcpPort
		srv.Host = "" // FIXME: Allow binding to specific IPs
	}
	srv.ConfigureAPI()

	return srv
}

// NewServer creates a server to handle health requests.
func NewServer(config Config) (*Server, error) {
	server := &Server{
		startTime:    time.Now(),
		Config:       config,
		tcpServers:   []*healthApi.Server{},
		connectivity: []*healthModels.NodeStatus{},
	}

	swaggerSpec, err := loads.Analyzed(healthApi.SwaggerJSON, "")
	if err != nil {
		return nil, err
	}

	if !config.Passive {
		cl, err := ciliumPkg.NewClient(config.CiliumURI)
		if err != nil {
			return nil, err
		}

		server.Client = cl
		server.Server = *server.newServer(swaggerSpec, 0)
	}
	for port := range PortToPaths {
		srv := server.newServer(swaggerSpec, port)
		server.tcpServers = append(server.tcpServers, srv)
	}

	return server, nil
}
