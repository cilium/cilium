package driver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	common "github.com/noironetworks/cilium-net/common"
	cnc "github.com/noironetworks/cilium-net/common/client"
	ciliumtype "github.com/noironetworks/cilium-net/common/types"

	log "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/Sirupsen/logrus"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/libnetwork/drivers/remote/api"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/libnetwork/types"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/gorilla/mux"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/vishvananda/netlink"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/k8s.io/kubernetes/pkg/registry/service/ipallocator"
)

const (
	DefaultPoolV4            = "CilliumPoolv4"
	DefaultPoolV6            = "CilliumPoolv6"
	LocalAllocSubnet         = "1.0.0.0/16" // Never exposed, used to generate IPv6 addr
	HostInterfacePrefix      = "lxc"
	TemporaryInterfacePrefix = "tmp"
	ContainerInterfacePrefix = "cilium"
	DummyV4AllocPool         = "0.0.0.0/0"  // Never exposed, makes libnetwork happy
	DummyV4Gateway           = "1.1.1.1/32" // Never exposed, makes libnetwork happy
)

type Driver interface {
	Listen(string) error
}

type driver struct {
	nodeAddress    net.IP
	allocPool      *net.IPNet
	allocatorRange *ipallocator.Range
	endpoints      map[string]*ciliumtype.Endpoint
	sync.Mutex
	client *cnc.Client
}

func endpoint2ifname(endpointID string) string {
	return HostInterfacePrefix + endpointID[:5]
}

func NewDriver(ctx *cli.Context) (Driver, error) {

	nodeAddress := net.ParseIP(ctx.String("node-addr"))
	if nodeAddress == nil {
		nodeAddrStr, err := common.GenerateV6Prefix()
		if err != nil {
			log.Fatalf("Unable to generate IPv6 prefix: %s\n", err)
		}

		log.Infof("Generated IPv6 prefix: %s\n", nodeAddrStr)

		nodeAddress = net.ParseIP(nodeAddrStr)
	}

	if !common.ValidNodeAddress(nodeAddress) {
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

	c, err := cnc.NewDefaultClient()
	if err != nil {
		log.Fatalf("Error while starting cilium-client: %s", err)
	}

	d := &driver{
		nodeAddress:    nodeAddress,
		allocPool:      subnet,
		allocatorRange: ipallocator.NewCIDRRange(v4Alloc),
		endpoints:      make(map[string]*ciliumtype.Endpoint),
		client:         c,
	}

	log.Infof("New Cilium networking instance on node %s", nodeAddress.String())
	log.Infof("Address pool: %s", subnet.String())

	return d, nil
}

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
	log.Warnf("plugin Not found: [ %+v ]", r)
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
		log.Warnf("No IPv6 address provided in CreateEndpoint request")
	}

	maps := make([]ciliumtype.EPPortMap, 0, 32)

	for key, val := range create.Options {
		switch key {
		case "com.docker.network.portmap":
			var portmap []types.PortBinding
			if err := json.Unmarshal(val, &portmap); err != nil {
				sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
				return
			}
			log.Debugf("PortBinding: %+v", &portmap)

			// FIXME: Host IP is ignored for now
			for _, m := range portmap {
				maps = append(maps, ciliumtype.EPPortMap{
					From:  m.HostPort,
					To:    m.Port,
					Proto: uint8(m.Proto),
				})
			}

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

	if _, exists := driver.endpoints[endID]; exists {
		sendError(w, "Endpoint already exists", http.StatusBadRequest)
		return
	}

	ip, _, _ := net.ParseCIDR(containerAddress)

	driver.endpoints[endID] = &ciliumtype.Endpoint{
		DockerID:      "",
		LxcIP:         ip,
		NodeIP:        driver.nodeAddress,
		DockerNetwork: create.NetworkID,
		PortMap:       maps,
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
	var del api.DeleteEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&del); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debugf("Delete endpoint request: %+v", &del)

	delete(driver.endpoints, del.EndpointID)
	deleteEndpointInterface(del.EndpointID)
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

	ep, exists := driver.endpoints[j.EndpointID]
	if !exists {
		sendError(w, "Endpoint does not exist", http.StatusBadRequest)
		return
	}

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

	peer, err := netlink.LinkByName(tmpIfname)
	if err != nil {
		sendError(w, "Unable to lookup veth peer just created: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := netlink.LinkSetMTU(peer, 1450); err != nil {
		sendError(w, "Unable to set MTU: "+err.Error(), http.StatusBadRequest)
		return
	}

	ep.LxcMAC = ciliumtype.MAC(peer.Attrs().HardwareAddr)

	nodeVeth, err := netlink.LinkByName(lxcIfname)
	if err != nil {
		sendError(w, "Unable to lookup veth pair just created: "+err.Error(), http.StatusBadRequest)
		return
	}
	ep.NodeMAC = ciliumtype.MAC(nodeVeth.Attrs().HardwareAddr)
	ep.IfIndex = nodeVeth.Attrs().Index

	if err := netlink.LinkSetUp(veth); err != nil {
		sendError(w, "Unable to bring up veth pair: "+err.Error(), http.StatusBadRequest)
		return
	}

	ifname := &api.InterfaceName{
		SrcName:   tmpIfname,
		DstPrefix: ContainerInterfacePrefix,
	}

	gw := driver.nodeAddress.String()

	ep.Ifname = lxcIfname
	ep.SetID()
	if err := driver.client.EndpointJoin(*ep); err != nil {
		log.Errorf("Joining endpoint failed: %s", err)
		// TODO: clean all of the stuff that we created so far
		sendError(w, "Unable to create BPF map: "+err.Error(), http.StatusInternalServerError)
	}

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

	if ep, exists := driver.endpoints[l.EndpointID]; !exists {
		log.Warnf("Endpoint %s is unknown", l.EndpointID)
	} else {
		if err := driver.client.EndpointLeave(ep.ID); err != nil {
			log.Warnf("Leaving the endpoint failed: %s", err)
		}
	}

	deleteEndpointInterface(l.EndpointID)
	emptyResponse(w)
}
