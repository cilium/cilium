//
// Copyright 2016 Authors of Cilium
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
//
package driver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cilium/cilium/common/addressing"
	cnc "github.com/cilium/cilium/common/client"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/plugins"
	"github.com/cilium/cilium/common/types"

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
	client      *cnc.Client
	nodeAddress net.IP
}

// NewDriver creates and returns a new Driver for the given ctx.
func NewDriver(ctx *cli.Context) (Driver, error) {
	var nodeAddress string
	c, err := cnc.NewDefaultClient()
	if err != nil {
		log.Fatalf("Error while starting cilium-client: %s", err)
	}

	for tries := 0; tries < 10; tries++ {
		if res, err := c.Ping(); err != nil {
			if tries == 9 {
				log.Fatalf("Unable to reach cilium daemon: %s", err)
			} else {
				log.Warningf("Waiting for cilium daemon to come up...")
			}
			time.Sleep(time.Duration(tries) * time.Second)
		} else {
			nodeAddress = res.NodeAddress
			log.Infof("Received node address from daemon: %s", nodeAddress)
			break
		}
	}

	d := &driver{
		client:      c,
		nodeAddress: net.ParseIP(nodeAddress),
	}

	log.Infof("New Cilium networking instance on node %s", nodeAddress)

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
	ipv6Address := create.Interface.AddressIPv6
	ipv4Address := create.Interface.Address

	if ipv4Address == "" {
		log.Warningf("No IPv4 address provided in CreateEndpoint request")
	}

	if ipv6Address == "" {
		sendError(w, "No IPv6 address provided (required)", http.StatusBadRequest)
		return
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

	ep, err := driver.client.EndpointGetByDockerEPID(endID)
	if err != nil {
		sendError(w, fmt.Sprintf("Error retrieving endpoint %s", err), http.StatusBadRequest)
		return
	}
	if ep != nil {
		sendError(w, "Endpoint already exists", http.StatusBadRequest)
		return
	}

	endpoint := types.Endpoint{
		NodeIP:           driver.nodeAddress,
		DockerNetworkID:  create.NetworkID,
		DockerEndpointID: endID,
		PortMap:          maps,
	}

	if ipv6Address != "" {
		ip6, _, err := net.ParseCIDR(ipv6Address)
		if err != nil {
			sendError(w, fmt.Sprintf("Invalid IPv6 address: %s", err), http.StatusBadRequest)
			return
		}
		endpoint.IPv6 = addressing.DeriveCiliumIPv6(ip6)
	}

	if ipv4Address != "" {
		ip4, _, err := net.ParseCIDR(ipv4Address)
		if err != nil {
			sendError(w, fmt.Sprintf("Invalid IPv4 address: %s", err), http.StatusBadRequest)
			return
		}
		endpoint.IPv4 = addressing.DeriveCiliumIPv4(ip4)
	}

	endpoint.SetID()

	if err = driver.client.EndpointSave(endpoint); err != nil {
		sendError(w, fmt.Sprintf("Error retrieving endpoint %s", err), http.StatusBadRequest)
		return
	}

	log.Debugf("Created Endpoint: %+v", endpoint)

	log.Infof("New endpoint %s with IPv6: %s, IPv4: %s", endID, ipv6Address, ipv4Address)

	respIface := &api.EndpointInterface{
		// Fixme: the lxcmac is an empty string at this point and we only know the
		// mac address at the end of joinEndpoint
		// There's no problem in the setup but docker inspect will show an empty mac address
		MacAddress: endpoint.LXCMAC.String(),
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

	ep, err := driver.client.EndpointGetByDockerEPID(j.EndpointID)
	if err != nil {
		sendError(w, fmt.Sprintf("Error retrieving endpoint %s", err), http.StatusBadRequest)
		return
	}
	if ep == nil {
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
	if err = driver.client.EndpointJoin(*ep); err != nil {
		log.Errorf("Joining endpoint failed: %s", err)
		sendError(w, "Unable to create BPF map: "+err.Error(), http.StatusInternalServerError)
	}

	rep, err := driver.client.GetIPAMConf(ipam.LibnetworkIPAMType, ipam.IPAMReq{})
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
	if rep.IPAMConfig.IP4 != nil {
		for _, route := range rep.IPAMConfig.IP4.Routes {
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
	}

	res := &api.JoinResponse{
		GatewayIPv6:           rep.IPAMConfig.IP6.Gateway.String(),
		InterfaceName:         ifname,
		StaticRoutes:          lnRoutes,
		DisableGatewayService: true,
	}

	// FIXME? Having the following code results on a runtime error: docker: Error
	// response from daemon: oci runtime error: process_linux.go:334: running prestart
	// hook 0 caused "exit status 1: time=\"2016-10-26T06:33:17-07:00\" level=fatal
	// msg=\"failed to set gateway while updating gateway: file exists\" \n"
	//
	// If empty, it works as expected without docker runtime errors
	// if rep.IPAMConfig.IP4 != nil {
	//	res.Gateway = rep.IPAMConfig.IP4.Gateway.String()
	// }
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

	if err := driver.client.EndpointLeaveByDockerEPID(l.EndpointID); err != nil {
		log.Warningf("Leaving the endpoint failed: %s", err)
	}

	if err := plugins.DelLinkByName(plugins.Endpoint2IfName(l.EndpointID)); err != nil {
		log.Warningf("Error while deleting link: %s", err)
	}
	emptyResponse(w)
}
