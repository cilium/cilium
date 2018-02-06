package envoy

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/completion"
	envoy_api "github.com/cilium/cilium/pkg/envoy/api"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/struct"
	"github.com/golang/protobuf/ptypes/wrappers"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Listener represents proxy configuration Envoy integration needs to
// know about. To be integrated with Cilium policy code.
type Listener struct {
	// Configuration
	proxyPort    uint16              // Proxy redirection port number
	listenerConf *envoy_api.Listener // Envoy Listener protobuf for this listener (const)

	// Policy
	l7rules policy.L7DataMap

	// Interface for access logging
	logger Logger

	// Derive from StreamControl to manage the Envoy RDS gRPC stream for this listener.
	StreamControl
}

// LDSServer represents an Envoy ListenerDiscoveryService gRPC server.
type LDSServer struct {
	path string // Path to unix domain socket to create

	lis  *net.UnixListener
	glds *grpc.Server
	rds  *RDSServer // Reference to RDS server serving route configurations.

	listenersMutex lock.RWMutex        // The rest protected by this
	listenerProto  *envoy_api.Listener // Generic Envoy Listener protobuf (const)
	listeners      map[string]*Listener
	envoyResources map[string]*Listener

	// Derive from StreamControl to manage an Envoy LDS gRPC stream.
	StreamControl
}

func createLDSServer(path, accessLogPath string) *LDSServer {
	ldsServer := &LDSServer{path: path, StreamControl: makeStreamControl("LDS")}

	os.Remove(path)
	var err error
	ldsServer.lis, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed to listen at ", path)
	}

	ldsServer.glds = grpc.NewServer()

	ldsServer.listenerProto = &envoy_api.Listener{
		Address: &envoy_api.Address{
			Address: &envoy_api.Address_SocketAddress{
				SocketAddress: &envoy_api.SocketAddress{
					Protocol: envoy_api.SocketAddress_TCP,
					Address:  "::",
					// PortSpecifier: &envoy_api.SocketAddress_PortValue{0},
				},
			},
		},
		FilterChains: []*envoy_api.FilterChain{{
			Filters: []*envoy_api.Filter{{
				Name: "envoy.http_connection_manager",
				Config: &structpb.Struct{Fields: map[string]*structpb.Value{
					"stat_prefix": {&structpb.Value_StringValue{StringValue: "proxy"}},
					"http_filters": {&structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
						{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name": {&structpb.Value_StringValue{StringValue: "cilium.l7policy"}},
							"config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"deprecated_v1": {&structpb.Value_BoolValue{BoolValue: true}},
								"value": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
									"access_log_path": {&structpb.Value_StringValue{StringValue: accessLogPath}},
								}}}},
							}}}},
							"deprecated_v1": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"type": {&structpb.Value_StringValue{StringValue: "decoder"}},
							}}}},
						}}}},
						{&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"name": {&structpb.Value_StringValue{StringValue: "envoy.router"}},
							"config": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"deprecated_v1": {&structpb.Value_BoolValue{BoolValue: true}},
							}}}},
							"deprecated_v1": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"type": {&structpb.Value_StringValue{StringValue: "decoder"}},
							}}}},
						}}}},
					}}}},
					"rds": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
						"config_source": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
							"api_config_source": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
								"api_type":     {&structpb.Value_NumberValue{NumberValue: float64(envoy_api.ApiConfigSource_GRPC)}},
								"cluster_name": {&structpb.Value_StringValue{StringValue: "rdsCluster"}},
							}}}},
						}}}},
						// "route_config_name": {&structpb.Value_StringValue{StringValue: "route_config_name"}},
					}}}},
				}},
				DeprecatedV1: &envoy_api.Filter_DeprecatedV1{
					Type: "read",
				},
			}},
		}},
		ListenerFilterChain: []*envoy_api.Filter{{
			Name: "cilium.bpf_metadata",
			Config: &structpb.Struct{Fields: map[string]*structpb.Value{
				"deprecated_v1": {&structpb.Value_BoolValue{BoolValue: true}},
				"value": {&structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
					"is_ingress": {&structpb.Value_BoolValue{BoolValue: false}},
				}}}},
			}},
			DeprecatedV1: &envoy_api.Filter_DeprecatedV1{
				Type: "accept",
			},
		}},
	}

	ldsServer.listeners = make(map[string]*Listener)
	ldsServer.envoyResources = make(map[string]*Listener)

	envoy_api.RegisterListenerDiscoveryServiceServer(ldsServer.glds, ldsServer)
	// Register reflection service on gRPC server.
	reflection.Register(ldsServer.glds)

	return ldsServer
}

func (s *LDSServer) addListener(name string, port uint16, l7rules policy.L7DataMap, isIngress bool, logger Logger, wg *completion.WaitGroup) {
	s.listenersMutex.Lock()
	log.Debug("Envoy: addListener ", name)

	// Bail out if this listener already exists
	if _, ok := s.listeners[name]; ok {
		log.Fatalf("Envoy: addListener: Listener %s already exists!", name)
	}

	resourceName := "RDS_" + name + "_" + strconv.FormatUint(s.currentVersion, 10)

	listener := &Listener{
		proxyPort:     port,
		l7rules:       l7rules,
		listenerConf:  proto.Clone(s.listenerProto).(*envoy_api.Listener),
		logger:        logger,
		StreamControl: makeStreamControl(resourceName),
	}

	// RDS server 'listener' lock not held, but no-one else has access to it yet.
	listener.addCompletion(wg, "addListener "+name)

	// Fill in the listener-specific parts
	listener.listenerConf.Name = name
	listener.listenerConf.Address.GetSocketAddress().PortSpecifier = &envoy_api.SocketAddress_PortValue{PortValue: uint32(port)}
	listener.listenerConf.FilterChains[0].Filters[0].Config.Fields["rds"].GetStructValue().Fields["route_config_name"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: resourceName}}
	if isIngress {
		listener.listenerConf.ListenerFilterChain[0].Config.Fields["value"].GetStructValue().Fields["is_ingress"].GetKind().(*structpb.Value_BoolValue).BoolValue = true
	}
	listener.listenerConf.FilterChains[0].Filters[0].Config.Fields["http_filters"].GetListValue().Values[0].GetStructValue().Fields["config"].GetStructValue().Fields["value"].GetStructValue().Fields["listener_id"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: resourceName}}
	s.listeners[name] = listener
	s.envoyResources[resourceName] = listener
	s.listenersMutex.Unlock()
	s.bumpVersion()
}

func (s *LDSServer) updateListener(name string, l7rules policy.L7DataMap, wg *completion.WaitGroup) {
	s.listenersMutex.Lock()
	defer s.listenersMutex.Unlock()
	log.Debug("Envoy: updateListener ", name)
	l := s.listeners[name]
	// Bail out if this listener does not exist
	if l == nil {
		log.Fatalf("Envoy: updateListener: Listener %s does not exist", name)
	}
	// The set of listeners did not change, so it suffices to
	// bump the version of the listener, which will trigger only an
	// RDS update to synchonize the new policy.
	l.bumpVersionFunc(func() { // func called while RDS server 'l' lock held
		l.l7rules = l7rules
		l.addCompletion(wg, "updateListener "+name)
	})
}

func (s *LDSServer) removeListener(name string, wg *completion.WaitGroup) {
	s.listenersMutex.Lock()
	log.Debug("Envoy: removeListener ", name)
	l := s.listeners[name]
	// Bail out if this listener does not exist
	if l == nil {
		log.Fatalf("Envoy: removeListener: Listener %s does not exist", name)
	}
	l.stopHandling()
	delete(s.listeners, name)
	delete(s.envoyResources, l.name)
	s.listenersMutex.Unlock()
	s.bumpVersionFunc(func() { // func called while LDS server 's' lock held
		s.addCompletion(wg, "removeListener "+name)
	})
}

// Find the listener given the Envoy Resource name
func (s *LDSServer) findListener(name string) *Listener {
	if s == nil {
		return nil
	}
	s.listenersMutex.Lock()
	defer s.listenersMutex.Unlock()

	return s.envoyResources[name]
}

func (s *LDSServer) run(rds *RDSServer) {
	s.rds = rds

	go func() {
		if err := s.glds.Serve(s.lis); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			log.WithError(err).Error("Envoy: Failed to serve LDS")
		}
	}()
}

func (s *LDSServer) stop() {
	s.glds.Stop()
	os.Remove(s.path)
}

// RDSServer represents an Envoy RouteDiscoveryService gRPC server.
type RDSServer struct {
	path string // Path to unix domain socket to create

	lis  *net.UnixListener
	grds *grpc.Server
	lds  *LDSServer // Reference to LDS server

	allowAction envoy_api.Route_Route // Pass route action to use in route rules (const)

	// Envoy opens an individual RDS stream for each Listener, so
	// the streams are managed by the individual Listeners.
}

func createRDSServer(path string, lds *LDSServer) *RDSServer {
	rdsServer := &RDSServer{path: path, lds: lds}

	os.Remove(path)
	var err error
	rdsServer.lis, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		log.WithError(err).Fatal("Envoy: Failed to listen at ", path)
	}

	rdsServer.grds = grpc.NewServer()

	rdsServer.allowAction = envoy_api.Route_Route{Route: &envoy_api.RouteAction{
		ClusterSpecifier: &envoy_api.RouteAction_Cluster{Cluster: "cluster1"},
	}}

	envoy_api.RegisterRouteDiscoveryServiceServer(rdsServer.grds, rdsServer)
	// Register reflection service on gRPC server.
	reflection.Register(rdsServer.grds)

	return rdsServer
}

func (s *RDSServer) run() {
	go func() {
		if err := s.grds.Serve(s.lis); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			log.WithError(err).Errorf("Envoy: Failed to serve RDS")
		}
	}()
}

func (s *RDSServer) stop() {
	s.grds.Stop()
	os.Remove(s.path)
}

func (s *RDSServer) translatePolicyRule(h api.PortRuleHTTP) *envoy_api.Route {
	// Count the number of header matches we need
	cnt := len(h.Headers)
	if h.Path != "" {
		cnt++
	}
	if h.Method != "" {
		cnt++
	}
	if h.Host != "" {
		cnt++
	}

	var ruleRef string
	isRegex := wrappers.BoolValue{Value: true}
	headers := make([]*envoy_api.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_api.HeaderMatcher{Name: ":path", Value: h.Path, Regex: &isRegex})
		ruleRef = `PathRegexp("` + h.Path + `")`
	}
	if h.Method != "" {
		headers = append(headers, &envoy_api.HeaderMatcher{Name: ":method", Value: h.Method, Regex: &isRegex})
		if ruleRef != "" {
			ruleRef += " && "
		}
		ruleRef += `MethodRegexp("` + h.Method + `")`
	}

	if h.Host != "" {
		headers = append(headers, &envoy_api.HeaderMatcher{Name: ":authority", Value: h.Host, Regex: &isRegex})
		if ruleRef != "" {
			ruleRef += " && "
		}
		ruleRef += `HostRegexp("` + h.Host + `")`
	}
	for _, hdr := range h.Headers {
		strs := strings.SplitN(hdr, " ", 2)
		if ruleRef != "" {
			ruleRef += " && "
		}
		ruleRef += `Header("`
		if len(strs) == 2 {
			// Remove ':' in "X-Key: true"
			key := strings.TrimRight(strs[0], ":")
			// Header presence and matching (literal) value needed.
			headers = append(headers, &envoy_api.HeaderMatcher{Name: key, Value: strs[1]})
			ruleRef += key + `","` + strs[1]
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_api.HeaderMatcher{Name: strs[0]})
			ruleRef += strs[0]
		}
		ruleRef += `")`
	}

	// Envoy v2 API has a Path Regex, but it has not been
	// implemented yet, so we must always match the root of the
	// path to not miss anything.
	return &envoy_api.Route{
		Match: &envoy_api.RouteMatch{
			PathSpecifier: &envoy_api.RouteMatch_Prefix{Prefix: "/"},
			Headers:       headers,
		},
		Action: &s.allowAction,
		Metadata: &envoy_api.Metadata{
			FilterMetadata: map[string]*structpb.Struct{
				"envoy.router": {Fields: map[string]*structpb.Value{
					"cilium_rule_ref": {&structpb.Value_StringValue{StringValue: ruleRef}},
				}},
			},
		},
	}
}

// FetchRoutes implements the gRPC serving of DiscoveryRequest for RouteDiscoveryService
func (s *RDSServer) FetchRoutes(ctx context.Context, req *envoy_api.DiscoveryRequest) (*envoy_api.DiscoveryResponse, error) {
	log.Debug("Envoy: RDS DiscoveryRequest: ", req.String())
	// Empty (or otherwise unparseable) string is treated as version zero.
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	var sendVersion uint64

	resources := make([]*any.Any, 0, len(req.ResourceNames))
	for _, name := range req.ResourceNames {
		l := s.lds.findListener(name)
		if l == nil {
			log.Error("Envoy: Listener ", name, " not found")
			continue
		}
		l.updateVersion(version)
		sendVersion = l.currentVersion
		resources = s.appendRoutes(resources, l)
	}

	return &envoy_api.DiscoveryResponse{
		VersionInfo: strconv.FormatUint(sendVersion, 10),
		Resources:   resources,
		Canary:      false,
		TypeUrl:     req.TypeUrl,
	}, nil
}

func (s *RDSServer) recv(rds envoy_api.RouteDiscoveryService_StreamRoutesServer) (uint64, []string, string, error) {
	req, err := rds.Recv()
	if err == io.EOF {
		return 0, nil, "", err
	}
	if err != nil {
		if !strings.Contains(err.Error(), "context canceled") {
			log.WithError(err).Errorf("Envoy: Failed to receive RDS request")
		}
		return 0, nil, "", err
	}
	log.Debug("Envoy: RDS Stream DiscoveryRequest ", req.String())
	// Empty (or otherwise unparseable) string is treated as version zero.
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	return version, req.ResourceNames, req.TypeUrl, nil
}

// StreamRoutes implements the gRPC bidirectional streaming of RouteDiscoveryService
func (s *RDSServer) StreamRoutes(rds envoy_api.RouteDiscoveryService_StreamRoutesServer) error {
	// deadline, ok := rds.Context().Deadline()

	// Envoy RDS syntax allows multiple listeners to be present in a single request, but it
	// currently opens an individual stream for each listener with RDS config.  This code should
	// handle both cases.  First stream to receive a request for a listener will handle it.

	var ctx StreamControlCtx

	// Read requests for this stream
	for {
		version, names, typeurl, err := s.recv(rds)
		if err != nil {
			if err == io.EOF {
				// Client closed stream.
				err = nil
			}
			break
		}

		for _, name := range names {
			// Queue an internal stream request for the routing info
			l := s.lds.findListener(name)
			if l == nil {
				log.Error("Envoy: RDS Listener ", name, " not found")
				continue
			}

			l.handleVersion(&ctx, version, func() error {
				return s.pushRoutes(rds, typeurl, l)
			})
		}
	}
	ctx.stop()
	return nil
}

// Called with streamcontrol mutex held.
func (s *RDSServer) pushRoutes(rds envoy_api.RouteDiscoveryService_StreamRoutesServer, typeurl string, listener *Listener) error {
	resources := make([]*any.Any, 0, 1)
	resources = s.appendRoutes(resources, listener)

	dr := &envoy_api.DiscoveryResponse{
		VersionInfo: strconv.FormatUint(listener.currentVersion, 10),
		Resources:   resources,
		Canary:      false,
		TypeUrl:     typeurl,
	}

	err := rds.Send(dr)
	if err != nil {
		log.WithError(err).Warning("Envoy: RDS Send() failed")
	}
	return err
}

func (s *RDSServer) appendRoutes(resources []*any.Any, listener *Listener) []*any.Any {
	routes := make([]*envoy_api.Route, 0, len(listener.l7rules))
	for _, ep := range listener.l7rules {
		// XXX: We should translate the fromEndpoints selector
		// (the key of the l7rules map) to a filter in Envoy
		// listener and not simply append the rules together.
		for _, h := range ep.HTTP {
			routes = append(routes, s.translatePolicyRule(h))
		}
	}
	routeconfig := &envoy_api.RouteConfiguration{
		Name: listener.name,
		VirtualHosts: []*envoy_api.VirtualHost{{
			Name:    listener.name,
			Domains: []string{"*"},
			Routes:  routes,
		}},
	}

	a, err := ptypes.MarshalAny(routeconfig)
	if err != nil {
		log.WithError(err).Error("Envoy: Marshaling Route failed")
	} else {
		resources = append(resources, a)
	}

	return resources
}

// FetchListeners implements the gRPC serving of DiscoveryRequest for ListenerDiscoveryService
func (s *LDSServer) FetchListeners(ctx context.Context, req *envoy_api.DiscoveryRequest) (*envoy_api.DiscoveryResponse, error) {
	s.listenersMutex.Lock()
	defer s.listenersMutex.Unlock()
	log.Debug("Envoy: LDS DiscoveryRequest: ", req.String())
	// Empty (or otherwise unparseable) string is treated as version zero.
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	s.updateVersion(version)
	return s.buildListeners(req.TypeUrl), nil
}

func (s *LDSServer) recv(lds envoy_api.ListenerDiscoveryService_StreamListenersServer) (uint64, string, error) {
	req, err := lds.Recv()
	if err == io.EOF {
		return 0, "", err
	}
	if err != nil {
		if !strings.Contains(err.Error(), "context canceled") {
			log.WithError(err).Warningf("Envoy: Failed to receive LDS request")
		}
		return 0, "", err
	}
	log.Debug("Envoy: LDS Stream DiscoveryRequest: ", req.String())
	// Empty (or otherwise unparseable) string is treated as version zero.
	version, _ := strconv.ParseUint(req.VersionInfo, 10, 64)
	return version, req.TypeUrl, nil
}

// StreamListeners implements the gRPC bidirectional streaming of ListenerDiscoveryService
func (s *LDSServer) StreamListeners(lds envoy_api.ListenerDiscoveryService_StreamListenersServer) error {
	// deadline, ok := lds.Context().Deadline()

	var ctx StreamControlCtx

	// Read requests for this stream
	for {
		version, typeurl, err := s.recv(lds)
		if err != nil {
			if err == io.EOF {
				// Client closed stream.
				err = nil
			}
			break
		}

		s.handleVersion(&ctx, version, func() error {
			return s.pushListeners(lds, typeurl)
		})
	}
	ctx.stop()
	return nil
}

// Called with streamcontrol mutex held.
func (s *LDSServer) pushListeners(lds envoy_api.ListenerDiscoveryService_StreamListenersServer, typeurl string) error {
	s.listenersMutex.Lock()
	defer s.listenersMutex.Unlock()

	err := lds.Send(s.buildListeners(typeurl))
	if err != nil {
		log.WithError(err).Warning("Envoy: LDS Send() failed")
	}
	return err
}

func (s *LDSServer) buildListeners(typeurl string) *envoy_api.DiscoveryResponse {
	resources := make([]*any.Any, 0, len(s.listeners))
	for _, l := range s.listeners {
		a, err := ptypes.MarshalAny(l.listenerConf)
		if err != nil {
			log.WithError(err).Fatal("Envoy: Marshaling Listener failed")
		} else {
			resources = append(resources, a)
		}
	}

	return &envoy_api.DiscoveryResponse{
		VersionInfo: strconv.FormatUint(s.currentVersion, 10),
		Resources:   resources,
		Canary:      false,
		TypeUrl:     typeurl,
	}
}

func createBootstrap(filePath string, name, cluster, version string, ldsName, ldsSock, rdsName, rdsSock string, envoyClusterName string, adminPort uint32) {
	bs := &envoy_api.Bootstrap{
		Node: &envoy_api.Node{Id: name, Cluster: cluster, Metadata: nil, Locality: nil, BuildVersion: version},
		StaticResources: &envoy_api.Bootstrap_StaticResources{
			Clusters: []*envoy_api.Cluster{
				{
					Name:            envoyClusterName,
					Type:            envoy_api.Cluster_ORIGINAL_DST,
					ConnectTimeout:  &duration.Duration{Seconds: 1, Nanos: 0},
					CleanupInterval: &duration.Duration{Seconds: 1, Nanos: 500000000},
					LbPolicy:        envoy_api.Cluster_ORIGINAL_DST_LB,
					AutoHttp2:       true,
				},
				{
					Name:           ldsName,
					Type:           envoy_api.Cluster_STATIC,
					ConnectTimeout: &duration.Duration{Seconds: 1, Nanos: 0},
					LbPolicy:       envoy_api.Cluster_ROUND_ROBIN,
					Hosts: []*envoy_api.Address{
						{
							Address: &envoy_api.Address_Pipe{
								Pipe: &envoy_api.Pipe{Path: ldsSock}},
						},
					},
					ProtocolOptions: &envoy_api.Cluster_Http2ProtocolOptions{
						Http2ProtocolOptions: &envoy_api.Http2ProtocolOptions{},
					},
				},
				{
					Name:           rdsName,
					Type:           envoy_api.Cluster_STATIC,
					ConnectTimeout: &duration.Duration{Seconds: 1, Nanos: 0},
					LbPolicy:       envoy_api.Cluster_ROUND_ROBIN,
					Hosts: []*envoy_api.Address{
						{
							Address: &envoy_api.Address_Pipe{
								Pipe: &envoy_api.Pipe{Path: rdsSock}},
						},
					},
					ProtocolOptions: &envoy_api.Cluster_Http2ProtocolOptions{
						Http2ProtocolOptions: &envoy_api.Http2ProtocolOptions{},
					},
				},
			},
		},
		DynamicResources: &envoy_api.Bootstrap_DynamicResources{
			LdsConfig: &envoy_api.ConfigSource{
				ConfigSourceSpecifier: &envoy_api.ConfigSource_ApiConfigSource{
					ApiConfigSource: &envoy_api.ApiConfigSource{
						ApiType:     envoy_api.ApiConfigSource_GRPC,
						ClusterName: []string{ldsName},
					},
				},
			},
		},
		Admin: &envoy_api.Admin{
			AccessLogPath: "/dev/null",
			Address: &envoy_api.Address{
				Address: &envoy_api.Address_SocketAddress{
					SocketAddress: &envoy_api.SocketAddress{
						Protocol:      envoy_api.SocketAddress_TCP,
						Address:       "127.0.0.1",
						PortSpecifier: &envoy_api.SocketAddress_PortValue{PortValue: adminPort},
					},
				},
			},
		},
	}

	log.Debug("Envoy: Bootstrap: ", bs.String())
	data, err := proto.Marshal(bs)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Marshaling bootstrap failed")
	}
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		log.WithError(err).Fatal("Envoy: Error writing Envoy bootstrap file")
	}
}
