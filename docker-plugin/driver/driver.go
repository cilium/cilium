package driver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	common "github.com/noironetworks/cilium-net/common"
	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/plugins"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/codegangsta/cli"
	"github.com/docker/libnetwork/drivers/remote/api"
	lnTypes "github.com/docker/libnetwork/types"
	"github.com/gorilla/mux"
	l "github.com/op/go-logging"
	"github.com/vishvananda/netlink"
)

var log = l.MustGetLogger("cilium-net-client")

const (
	// ContainerInterfacePrefix is the container's internal interface name prefix.
	ContainerInterfacePrefix = "cilium"
)

// Driver interface that listens for docker requests.
type Driver interface {
	Listen(string) error
}

type driver struct {
	nodeAddress net.IP
	endpoints   map[string]*types.Endpoint
	sync.Mutex
	client *cnc.Client
}

// NewDriver creates and returns a new Driver for the given ctx.
func NewDriver(ctx *cli.Context) (Driver, error) {

	nodeAddress := net.ParseIP(ctx.String("node-addr"))
	if !common.ValidNodeAddress(nodeAddress) {
		log.Fatalf("Invalid node address: %s", nodeAddress)
	}

	c, err := cnc.NewDefaultClient()
	if err != nil {
		log.Fatalf("Error while starting cilium-client: %s", err)
	}

	for tries := 10; tries > 0; tries-- {
		if res, err := c.Ping(); err != nil {
			if tries == 1 {
				log.Fatalf("Unable to reach cilium daemon: %s", err)
			} else {
				log.Warningf("Waiting for cilium daemon to come up...")
			}
			time.Sleep(time.Second)
		} else {
			if nodeAddress == nil {
				nodeAddress = net.ParseIP(res.NodeAddress)
				log.Infof("Received node address from daemon: %s", nodeAddress)
			}

			break
		}
	}

	d := &driver{
		nodeAddress: nodeAddress,
		endpoints:   make(map[string]*types.Endpoint),
		client:      c,
	}

	log.Infof("New Cilium networking instance on node %s", nodeAddress.String())

	return d, nil
}

// Listen listens for docker requests on a particular set of endpoints on the given
// socket path.
func (driver *driver) Listen(socket string) error {
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(notFound)

	handleMethod := func(method string, h http.HandlerFunc) {
		router.Methods("POST").Path(fmt.Sprintf("/%s", method)).HandlerFunc(h)
	}

	handleMethod("Plugin.Activate", driver.handshake)
	handleMethod("NetworkDriver.GetCapabilities", driver.capabilities)
	handleMethod("NetworkDriver.CreateNetwork", driver.createNetwork)
	handleMethod("NetworkDriver.DeleteNetwork", driver.deleteNetwork)
	handleMethod("NetworkDriver.CreateEndpoint", driver.createEndpoint)
	handleMethod("NetworkDriver.DeleteEndpoint", driver.deleteEndpoint)
	handleMethod("NetworkDriver.EndpointOperInfo", driver.infoEndpoint)
	handleMethod("NetworkDriver.Join", driver.joinEndpoint)
	handleMethod("NetworkDriver.Leave", driver.leaveEndpoint)
	handleMethod("IpamDriver.GetCapabilities", driver.ipamCapabilities)
	handleMethod("IpamDriver.GetDefaultAddressSpaces", driver.getDefaultAddressSpaces)
	handleMethod("IpamDriver.RequestPool", driver.requestPool)
	handleMethod("IpamDriver.ReleasePool", driver.releasePool)
	handleMethod("IpamDriver.RequestAddress", driver.requestAddress)
	handleMethod("IpamDriver.ReleaseAddress", driver.releaseAddress)
	var (
		listener net.Listener
		err      error
	)

	listener, err = net.Listen("unix", socket)
	if err != nil {
		return err
	}

	return http.Serve(listener, router)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	log.Warningf("plugin Not found: [ %+v ]", r)
	http.NotFound(w, r)
}

func sendError(w http.ResponseWriter, msg string, code int) {
	log.Errorf("%d %s", code, msg)
	http.Error(w, msg, code)
}

func objectResponse(w http.ResponseWriter, obj interface{}) {
	if err := json.NewEncoder(w).Encode(obj); err != nil {
		sendError(w, "Could not JSON encode response", http.StatusInternalServerError)
		return
	}
}

func emptyResponse(w http.ResponseWriter) {
	json.NewEncoder(w).Encode(map[string]string{})
}

type handshakeResp struct {
	Implements []string
}

func (driver *driver) handshake(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(&handshakeResp{
		[]string{"NetworkDriver", "IpamDriver"},
	})
	if err != nil {
		log.Fatalf("handshake encode: %s", err)
		sendError(w, "encode error", http.StatusInternalServerError)
		return
	}
	log.Debug("Handshake completed")
}

func (driver *driver) capabilities(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(&api.GetCapabilityResponse{
		Scope: "local",
	})
	if err != nil {
		log.Fatalf("capabilities encode: %s", err)
		sendError(w, "encode error", http.StatusInternalServerError)
		return
	}
	log.Debug("NetworkDriver capabilities exchange complete")
}

func (driver *driver) createNetwork(w http.ResponseWriter, r *http.Request) {
	var create api.CreateNetworkRequest
	err := json.NewDecoder(r.Body).Decode(&create)
	if err != nil {
		sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Debugf("Network Create Called: [ %+v ]", create)
	emptyResponse(w)
}

func (driver *driver) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	var delete api.DeleteNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&delete); err != nil {
		sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Debugf("Delete network request: %+v", &delete)
	emptyResponse(w)
}

// CreateEndpointRequest is the as api.CreateEndpointRequest but with
// json.RawMessage type for Options map
type CreateEndpointRequest struct {
	NetworkID  string
	EndpointID string
	Interface  api.EndpointInterface
	Options    map[string]json.RawMessage
}

func (driver *driver) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var create CreateEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&create); err != nil {
		sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Debugf("Create endpoint request: %+v", &create)

	endID := create.EndpointID
	containerAddress := create.Interface.AddressIPv6
	if containerAddress == "" {
		log.Warningf("No IPv6 address provided in CreateEndpoint request")
	}

	maps := make([]types.EPPortMap, 0, 32)

	for key, val := range create.Options {
		switch key {
		case "com.docker.network.portmap":
			var portmap []lnTypes.PortBinding
			if err := json.Unmarshal(val, &portmap); err != nil {
				sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
				return
			}
			log.Debugf("PortBinding: %+v", &portmap)

			// FIXME: Host IP is ignored for now
			for _, m := range portmap {
				maps = append(maps, types.EPPortMap{
					From:  m.HostPort,
					To:    m.Port,
					Proto: uint8(m.Proto),
				})
			}

		case "com.docker.network.endpoint.exposedports":
			var tp []lnTypes.TransportPort
			if err := json.Unmarshal(val, &tp); err != nil {
				sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
				return
			}
			log.Debugf("ExposedPorts: %+v", &tp)
			// TODO: handle exposed ports
		}
	}

	if _, exists := driver.endpoints[endID]; exists {
		sendError(w, "Endpoint already exists", http.StatusBadRequest)
		return
	}

	ip, _, _ := net.ParseCIDR(containerAddress)

	driver.endpoints[endID] = &types.Endpoint{
		DockerID:         "",
		LXCIP:            ip,
		NodeIP:           driver.nodeAddress,
		DockerNetworkID:  create.NetworkID,
		DockerEndpointID: endID,
		PortMap:          maps,
	}

	log.Debugf("Created Endpoint: %+v", driver.endpoints[endID])

	log.Infof("New endpoint %s with IP %s", endID, containerAddress)

	respIface := &api.EndpointInterface{
		MacAddress: common.DefaultContainerMAC,
	}
	resp := &api.CreateEndpointResponse{
		Interface: respIface,
	}
	log.Debugf("Create endpoint response: %+v", resp)
	objectResponse(w, resp)
}

func (driver *driver) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var del api.DeleteEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&del); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debugf("Delete endpoint request: %+v", &del)

	delete(driver.endpoints, del.EndpointID)
	if err := plugins.DelLinkByName(plugins.Endpoint2IfName(del.EndpointID)); err != nil {
		log.Warningf("Error while deleting link: %s", err)
	}

	emptyResponse(w)
}

func (driver *driver) infoEndpoint(w http.ResponseWriter, r *http.Request) {
	var info api.EndpointInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debugf("Endpoint info request: %+v", &info)
	objectResponse(w, &api.EndpointInfoResponse{Value: map[string]interface{}{}})
	log.Debugf("Endpoint info %s", info.EndpointID)
}

func (driver *driver) joinEndpoint(w http.ResponseWriter, r *http.Request) {
	var (
		j   api.JoinRequest
		err error
	)
	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debugf("Join request: %+v", &j)

	ep, exists := driver.endpoints[j.EndpointID]
	if !exists {
		sendError(w, "Endpoint does not exist", http.StatusBadRequest)
		return
	}

	veth, _, tmpIfName, err := plugins.SetupVeth(j.EndpointID, 1450, ep)
	if err != nil {
		sendError(w, "Error while setting up veth pair: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				log.Warningf("failed to clean up veth %q: %s", veth.Name, err)
			}
		}
	}()

	ifname := &api.InterfaceName{
		SrcName:   tmpIfName,
		DstPrefix: ContainerInterfacePrefix,
	}

	ep.SetID()
	if err = driver.client.EndpointJoin(*ep); err != nil {
		log.Errorf("Joining endpoint failed: %s", err)
		sendError(w, "Unable to create BPF map: "+err.Error(), http.StatusInternalServerError)
	}

	rep, err := driver.client.GetIPAMConf(types.LibnetworkIPAMType, types.IPAMReq{})
	if err != nil {
		sendError(w, fmt.Sprintf("Could not get cilium IPAM configuration: %s", err), http.StatusBadRequest)
	}

	lnRoutes := []api.StaticRoute{}
	for _, route := range rep.IPAMConfig.IP6.Routes {
		nh := ""
		if route.IsL3() {
			nh = route.NextHop.String()
		}
		lnRoute := api.StaticRoute{
			Destination: route.Destination.String(),
			RouteType:   route.Type,
			NextHop:     nh,
		}
		lnRoutes = append(lnRoutes, lnRoute)
	}

	res := &api.JoinResponse{
		GatewayIPv6:           rep.IPAMConfig.IP6.Gateway.String(),
		InterfaceName:         ifname,
		StaticRoutes:          lnRoutes,
		DisableGatewayService: true,
	}

	log.Debugf("Join response: %+v", res)
	objectResponse(w, res)
}

func (driver *driver) leaveEndpoint(w http.ResponseWriter, r *http.Request) {
	var l api.LeaveRequest
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debugf("Leave request: %+v", &l)

	if ep, exists := driver.endpoints[l.EndpointID]; !exists {
		log.Warningf("Endpoint %s is unknown", l.EndpointID)
	} else {
		if err := driver.client.EndpointLeave(ep.ID); err != nil {
			log.Warningf("Leaving the endpoint failed: %s", err)
		}
	}

	if err := plugins.DelLinkByName(plugins.Endpoint2IfName(l.EndpointID)); err != nil {
		log.Warningf("Error while deleting link: %s", err)
	}
	emptyResponse(w)
}
