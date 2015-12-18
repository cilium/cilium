package driver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/libnetwork/drivers/remote/api"
	ipam "github.com/docker/libnetwork/ipams/remote/api"
	"github.com/docker/libnetwork/types"
	"github.com/gorilla/mux"
	"github.com/vishvananda/netlink"
	"k8s.io/kubernetes/pkg/registry/service/ipallocator"

	. "github.com/cilium-team/cilium-net/common"
)

const (
	DefaultPoolV4            = "CilliumPoolv4"
	DefaultPoolV6            = "CilliumPoolv6"
	LocalAllocSubnet         = "1.0.0.0/8" // Never exposed, used to generate IPv6 addr
	HostInterfacePrefix      = "lxc"
	TemporaryInterfacePrefix = "tmp"
	ContainerInterfacePrefix = "cilium"
	DummyV4AllocPool         = "0.0.0.0/0"  // Never exposed, makes libnetwork happy
	DummyV4Gateway           = "1.1.1.1/32" // Never exposed, makes libnetwork happy
	ContainerMAC             = "AA:BB:CC:DD:EE:FF"
)

type Driver interface {
	Listen(string) error
}

type driver struct {
	nodeAddress    net.IP
	allocPool      *net.IPNet
	allocatorRange *ipallocator.Range
	sync.Mutex
}

func endpoint2ifname(endpointID string) string {
	return HostInterfacePrefix + endpointID[:5]
}

func New(ctx *cli.Context) (Driver, error) {

	nodeAddress := net.ParseIP(ctx.String("node-addr"))
	if nodeAddress == nil {
		log.Fatalf("No node address given, please specifcy node address using -n")
	}

	if !ValidNodeAddress(nodeAddress) {
		log.Fatalf("Invalid node address: %s", nodeAddress)
	}

	_, subnet, err := net.ParseCIDR(nodeAddress.String() + "/64")
	if err != nil {
		log.Fatalf("Invalid CIDR %s", nodeAddress.String())
	}

	// Temporary hack. We use the IPv4 allocator from k8s to generate the
	// last 4 bytes of the local endpoint address
	_, v4Alloc, err := net.ParseCIDR(LocalAllocSubnet)
	if err != nil {
		log.Fatalf("Invalid CIDR %s", LocalAllocSubnet)
	}

	d := &driver{
		nodeAddress:    nodeAddress,
		allocPool:      subnet,
		allocatorRange: ipallocator.NewCIDRRange(v4Alloc),
	}

	log.Infof("New Cilium networking instance on node %s", nodeAddress.String())
	log.Infof("Address pool: %s", subnet.String())

	return d, nil
}

func (driver *driver) Listen(socket string) error {
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(notFound)

	router.Methods("POST").Path("/Plugin.Activate").HandlerFunc(driver.handshake)
	router.Methods("POST").Path("/NetworkDriver.GetCapabilities").HandlerFunc(driver.capabilities)

	handleMethod := func(method string, h http.HandlerFunc) {
		router.Methods("POST").Path(fmt.Sprintf("/%s", method)).HandlerFunc(h)
	}
	handleMethod("NetworkDriver.CreateNetwork", driver.createNetwork)
	handleMethod("NetworkDriver.DeleteNetwork", driver.deleteNetwork)
	handleMethod("NetworkDriver.CreateEndpoint", driver.createEndpoint)
	handleMethod("NetworkDriver.DeleteEndpoint", driver.deleteEndpoint)
	handleMethod("NetworkDriver.EndpointOperInfo", driver.infoEndpoint)
	handleMethod("NetworkDriver.Join", driver.joinEndpoint)
	handleMethod("NetworkDriver.Leave", driver.leaveEndpoint)
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
	log.Warnf("plugin Not found: [ %+v ]", r)
	http.NotFound(w, r)
}

func sendError(w http.ResponseWriter, msg string, code int) {
	log.Errorf("%d %s", code, msg)
	http.Error(w, msg, code)
}

func errorResponsef(w http.ResponseWriter, fmtString string, item ...interface{}) {
	json.NewEncoder(w).Encode(map[string]string{
		"Err": fmt.Sprintf(fmtString, item...),
	})
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
	log.Debug("Capabilities exchange complete")
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

// Same as api.CreateEndpointRequest but with json.RawMessage type for Options map
type CreateEndpointRequest struct {
	NetworkID  string
	EndpointID string
	Interface  *api.EndpointInterface
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
	containerAddress := create.Interface.Address

	for key, val := range create.Options {
		switch key {
		case "com.docker.network.portmap":
			var portmap []types.PortBinding
			if err := json.Unmarshal(val, &portmap); err != nil {
				sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
				return
			}
			log.Debugf("PortBinding: %+v", &portmap)
			// TODO: handle port binding
		case "com.docker.network.endpoint.exposedports":
			var tp []types.TransportPort
			if err := json.Unmarshal(val, &tp); err != nil {
				sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
				return
			}
			log.Debugf("ExposedPorts: %+v", &tp)
			// TODO: handle exposed ports
		}
	}

	// TODO: Keep track of this network association for automatic policy generation
	// create.NetworkID

	log.Infof("New endpoint %s with IP %s", endID, containerAddress)

	respIface := &api.EndpointInterface{
		MacAddress: ContainerMAC,
	}
	resp := &api.CreateEndpointResponse{
		Interface: respIface,
	}
	log.Debugf("Create endpoint response: %+v", resp)
	objectResponse(w, resp)
}

func deleteEndpointInterface(endpointID string) {
	ifname := endpoint2ifname(endpointID)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		log.Errorf("Could not find host-side container link %s: [ %s ]", ifname, err)
		return
	}

	// Just in case we did not receive a leave notification for this endpoint
	// interface should have already been deleted by the leave handler
	netlink.LinkDel(link)
}

func (driver *driver) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var delete api.DeleteEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&delete); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debugf("Delete endpoint request: %+v", &delete)

	deleteEndpointInterface(delete.EndpointID)
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
	var j api.JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debugf("Join request: %+v", &j)

	lxcIfname := endpoint2ifname(j.EndpointID)
	tmpIfname := TemporaryInterfacePrefix + j.EndpointID[:5]
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: lxcIfname},
		PeerName:  tmpIfname,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		sendError(w, "Unable to create veth pair: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Debugf("Created veth pair %s <-> %s", lxcIfname, veth.PeerName)

	if err := netlink.LinkSetMTU(veth, 1450); err != nil {
		sendError(w, "Unable to set MTU: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		sendError(w, "Unable to bring up veth pair: "+err.Error(), http.StatusBadRequest)
		return
	}

	ifname := &api.InterfaceName{
		SrcName:   tmpIfname,
		DstPrefix: ContainerInterfacePrefix,
	}

	gw := driver.nodeAddress.String()

	routeGW := api.StaticRoute{
		Destination: gw + "/128",
		RouteType:   types.CONNECTED,
		NextHop:     "",
	}

	routeDefault := api.StaticRoute{
		Destination: "::/0",
		RouteType:   types.NEXTHOP,
		NextHop:     driver.nodeAddress.String(),
	}

	res := &api.JoinResponse{
		GatewayIPv6:           gw,
		InterfaceName:         ifname,
		StaticRoutes:          []api.StaticRoute{routeGW, routeDefault},
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

	deleteEndpointInterface(l.EndpointID)
	emptyResponse(w)
}

///////////////////////////////////////////////////////////////////////////////
//
// IPAM
//
///////////////////////////////////////////////////////////////////////////////

func (driver *driver) getDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	log.Debugf("GetDefaultAddressSpaces Called")

	resp := &ipam.GetAddressSpacesResponse{
		LocalDefaultAddressSpace:  "CiliumLocal",
		GlobalDefaultAddressSpace: "CiliumGlobal",
	}

	log.Debugf("Get Default Address Spaces response: %+v", resp)
	objectResponse(w, resp)
}

func (driver *driver) requestPool(w http.ResponseWriter, r *http.Request) {
	var req ipam.RequestPoolRequest
	var poolID, pool, gw string

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Request Pool request: %+v", &req)

	if req.V6 == false {
		log.Warnf("Docker requested us to use legacy IPv4, boooooring...")
		poolID = DefaultPoolV4
		pool = DummyV4AllocPool
		gw = DummyV4Gateway
	} else {
		poolID = DefaultPoolV6
		pool = driver.allocPool.String()
		gw = driver.nodeAddress.String() + "/128"
	}

	resp := &ipam.RequestPoolResponse{
		PoolID: poolID,
		Pool:   pool,
		Data: map[string]string{
			"com.docker.network.gateway": gw,
		},
	}

	log.Debugf("Request Pool response: %+v", resp)
	objectResponse(w, resp)
}

func (driver *driver) releasePool(w http.ResponseWriter, r *http.Request) {
	var release ipam.ReleasePoolRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Release Pool request: %+v", &release)

	emptyResponse(w)
}

func (driver *driver) requestAddress(w http.ResponseWriter, r *http.Request) {
	var request ipam.RequestAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Request Address request: %+v", &request)

	var resp *ipam.RequestAddressResponse

	if request.PoolID == DefaultPoolV4 {
		/* Ignore */
	} else {
		v4IP, err := driver.allocatorRange.AllocateNext()
		if err != nil {
			sendError(w, "Could not allocate IP address", http.StatusBadRequest)
			return
		}

		ip := BuildEndpointAddress(driver.nodeAddress, v4IP)
		resp = &ipam.RequestAddressResponse{
			Address: ip.String() + "/128",
		}
	}

	log.Debugf("Request Address response: %+v", resp)
	objectResponse(w, resp)
}

func (driver *driver) releaseAddress(w http.ResponseWriter, r *http.Request) {
	var release ipam.ReleaseAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Release Address request: %+v", &release)

	err := driver.allocatorRange.Release(net.ParseIP(release.Address))
	if err != nil {
		sendError(w, "Unable to release IP address", http.StatusBadRequest)
		return
	}

	emptyResponse(w)
}
