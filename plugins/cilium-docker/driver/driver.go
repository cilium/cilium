// Copyright 2016-2017 Authors of Cilium
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

package driver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/plugins"
	"github.com/cilium/cilium/pkg/client"
	endpointPkg "github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logfields"

	"github.com/docker/libnetwork/drivers/remote/api"
	lnTypes "github.com/docker/libnetwork/types"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	// ContainerInterfacePrefix is the container's internal interface name prefix.
	ContainerInterfacePrefix = "cilium"
)

// Driver interface that listens for docker requests.
type Driver interface {
	Listen(string) error
}

type driver struct {
	client      *client.Client
	conf        models.DaemonConfigurationResponse
	routes      []api.StaticRoute
	gatewayIPv6 string
	gatewayIPv4 string
}

func endpointID(id string) string {
	return endpointPkg.NewID(endpointPkg.DockerEndpointPrefix, id)
}

func newLibnetworkRoute(route plugins.Route) api.StaticRoute {
	rt := api.StaticRoute{
		Destination: route.Prefix.String(),
		RouteType:   lnTypes.CONNECTED,
	}

	if route.Nexthop != nil {
		rt.NextHop = route.Nexthop.String()
		rt.RouteType = lnTypes.NEXTHOP
	}

	return rt
}

// NewDriver creates and returns a new Driver for the given API URL
func NewDriver(url string) (Driver, error) {
	scopedLog := log.WithField("url", url)
	c, err := client.NewClient(url)
	if err != nil {
		scopedLog.WithError(err).Fatal("Error while starting cilium-client")
	}

	d := &driver{client: c}

	for tries := 0; tries < 24; tries++ {
		if res, err := c.ConfigGet(); err != nil {
			if tries == 23 {
				scopedLog.WithError(err).Fatal("Unable to connect to cilium daemon")
			} else {
				scopedLog.Info("Waiting for cilium daemon to start up...")
			}
			time.Sleep(time.Duration(tries) * time.Second)
		} else {
			if res.Addressing == nil || res.Addressing.IPV6 == nil {
				scopedLog.Fatal("Invalid addressing information from daemon")
			}

			d.conf = *res
			break
		}
	}

	if err := plugins.SufficientAddressing(d.conf.Addressing); err != nil {
		scopedLog.WithError(err).Fatal("Insufficient addressing")
	}

	d.routes = []api.StaticRoute{}
	if d.conf.Addressing.IPV6 != nil {
		if routes, err := plugins.IPv6Routes(d.conf.Addressing); err != nil {
			scopedLog.WithError(err).Fatal("Unable to generate IPv6 routes")
		} else {
			for _, r := range routes {
				d.routes = append(d.routes, newLibnetworkRoute(r))
			}
		}

		d.gatewayIPv6 = plugins.IPv6Gateway(d.conf.Addressing)
	}

	if d.conf.Addressing.IPV4 != nil {
		if routes, err := plugins.IPv4Routes(d.conf.Addressing); err != nil {
			scopedLog.WithError(err).Fatal("Unable to generate IPv4 routes")
		} else {
			for _, r := range routes {
				d.routes = append(d.routes, newLibnetworkRoute(r))
			}
		}

		d.gatewayIPv4 = plugins.IPv6Gateway(d.conf.Addressing)
	}

	scopedLog.Info("Cilium Docker plugin ready")

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

	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	return http.Serve(listener, router)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	log.WithField(logfields.Object, logfields.Repr(r)).Warn("plugin Not found")
	http.NotFound(w, r)
}

func sendError(w http.ResponseWriter, msg string, code int) {
	log.WithFields(log.Fields{
		"code": code,
		"msg":  msg,
	}).Error("Sending error")
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
		log.WithError(err).Fatal("handshake encode")
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
		log.WithError(err).Fatal("capabilities encode")
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
	log.WithField(logfields.Request, logfields.Repr(&create)).Debug("Network Create Called")
	emptyResponse(w)
}

func (driver *driver) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	var delete api.DeleteNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&delete); err != nil {
		sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.WithField(logfields.Request, logfields.Repr(&delete)).Debug("Delete network request")
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
	log.WithField(logfields.Request, logfields.Repr(&create)).Debug("Create endpoint request")

	if create.Interface.Address == "" {
		log.Warn("No IPv4 address provided in CreateEndpoint request")
	}

	if create.Interface.AddressIPv6 == "" {
		sendError(w, "No IPv6 address provided (required)", http.StatusBadRequest)
		return
	}

	//	maps := make([]endpoint.PortMap, 0, 32)
	//
	//	for key, val := range create.Options {
	//		switch key {
	//		case "com.docker.network.portmap":
	//			var portmap []lnTypes.PortBinding
	//			if err := json.Unmarshal(val, &portmap); err != nil {
	//				sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
	//				return
	//			}
	//			log.WithField(logfields.Object, logfields.Repr(portmap)).Debug("PortBinding:")
	//
	//			// FIXME: Host IP is ignored for now
	//			for _, m := range portmap {
	//				maps = append(maps, endpoint.PortMap{
	//					From:  m.HostPort,
	//					To:    m.Port,
	//					Proto: uint8(m.Proto),
	//				})
	//			}
	//
	//		case "com.docker.network.endpoint.exposedports":
	//			var tp []lnTypes.TransportPort
	//			if err := json.Unmarshal(val, &tp); err != nil {
	//				sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
	//				return
	//			}
	//			log.WithField(logfields.Object, logfields.Repr(&tp)).Debug("ExposedPorts")
	//			// TODO: handle exposed ports
	//		}
	//	}

	_, err := driver.client.EndpointGet(endpointID(create.EndpointID))
	if err != nil {
		switch err.(type) {
		case *endpoint.GetEndpointIDNotFound:
			// Expected result
		default:
			sendError(w, fmt.Sprintf("Error retrieving endpoint %s", err), http.StatusBadRequest)
			return
		}
	} else {
		sendError(w, "Endpoint already exists", http.StatusBadRequest)
		return
	}

	ip6, err := addressing.NewCiliumIPv6(create.Interface.AddressIPv6)
	if err != nil {
		sendError(w, fmt.Sprintf("Unable to parse IPv6 address: %s", err),
			http.StatusBadRequest)
		return
	}

	endpoint := &models.EndpointChangeRequest{
		ID:               int64(ip6.EndpointID()),
		State:            models.EndpointStateDisconnected,
		DockerEndpointID: create.EndpointID,
		DockerNetworkID:  create.NetworkID,
		Addressing: &models.EndpointAddressing{
			IPV6: ip6.String(),
			IPV4: create.Interface.Address,
		},
	}

	// FIXME: Translate port mappings to RuleL4 policy elements

	if err = driver.client.EndpointCreate(endpoint); err != nil {
		sendError(w, fmt.Sprintf("Error creating endpoint %s", err), http.StatusBadRequest)
		return
	}

	log.WithField(logfields.EndpointID, create.EndpointID).Debug("Created new endpoint")

	respIface := &api.EndpointInterface{
		// Fixme: the lxcmac is an empty string at this point and we only know the
		// mac address at the end of joinEndpoint
		// There's no problem in the setup but docker inspect will show an empty mac address
		MacAddress: "",
	}
	resp := &api.CreateEndpointResponse{
		Interface: respIface,
	}
	log.WithField(logfields.Response, logfields.Repr(resp)).Debug("Create endpoint response")
	objectResponse(w, resp)
}

func (driver *driver) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var del api.DeleteEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&del); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.WithField(logfields.Request, logfields.Repr(&del)).Debug("Delete endpoint request")

	if err := plugins.DelLinkByName(plugins.Endpoint2IfName(del.EndpointID)); err != nil {
		log.WithError(err).Warn("Error while deleting link")
	}

	emptyResponse(w)
}

func (driver *driver) infoEndpoint(w http.ResponseWriter, r *http.Request) {
	var info api.EndpointInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.WithField(logfields.Request, logfields.Repr(&info)).Debug("Endpoint info request")
	objectResponse(w, &api.EndpointInfoResponse{Value: map[string]interface{}{}})
	log.WithField(logfields.Response, info.EndpointID).Debug("Endpoint info")
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
	log.WithField(logfields.Request, logfields.Repr(&j)).Debug("Join request")

	old, err := driver.client.EndpointGet(endpointID(j.EndpointID))
	if err != nil {
		sendError(w, fmt.Sprintf("Error retrieving endpoint %s", err), http.StatusBadRequest)
		return
	}

	log.WithField(logfields.Object, old).Debug("Existing endpoint")
	if old.State != models.EndpointStateDisconnected {
		sendError(w, "Error: endpoint not in disconnected state", http.StatusBadRequest)
		return
	}

	ep := &models.EndpointChangeRequest{
		State: models.EndpointStateWaitingForIdentity,
	}

	veth, _, tmpIfName, err := plugins.SetupVeth(j.EndpointID, 1450, ep)
	if err != nil {
		sendError(w, "Error while setting up veth pair: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				log.WithError(err).WithField(logfields.Veth, veth.Name).Warn("failed to clean up veth")
			}
		}
	}()

	if err = driver.client.EndpointPatch(endpointPkg.NewCiliumID(old.ID), ep); err != nil {
		log.WithError(err).Error("Joining endpoint failed")
		sendError(w, "Unable to connect endpoint to network: "+err.Error(),
			http.StatusInternalServerError)
	}

	res := &api.JoinResponse{
		InterfaceName: &api.InterfaceName{
			SrcName:   tmpIfName,
			DstPrefix: ContainerInterfacePrefix,
		},
		StaticRoutes:          driver.routes,
		DisableGatewayService: true,
		GatewayIPv6:           driver.gatewayIPv6,
		//GatewayIPv4:           driver.gatewayIPv4,
	}

	// FIXME? Having the following code results on a runtime error: docker: Error
	// response from daemon: oci runtime error: process_linux.go:334: running prestart
	// hook 0 caused "exit status 1: time=\"2016-10-26T06:33:17-07:00\" level=fatal
	// msg=\"failed to set gateway while updating gateway: file exists\" \n"
	//
	// If empty, it works as expected without docker runtime errors
	// res.Gateway = plugins.IPv4Gateway(addr)

	log.WithField(logfields.Response, logfields.Repr(res)).Debug("Join response")
	objectResponse(w, res)
}

func (driver *driver) leaveEndpoint(w http.ResponseWriter, r *http.Request) {
	var l api.LeaveRequest
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.WithField(logfields.Request, logfields.Repr(&l)).Debug("Leave request")

	if err := driver.client.EndpointDelete(endpointID(l.EndpointID)); err != nil {
		log.WithError(err).Warn("Leaving the endpoint failed")
	}

	emptyResponse(w)
}
