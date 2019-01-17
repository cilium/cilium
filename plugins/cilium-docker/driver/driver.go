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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/route"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	endpointIDPkg "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/docker/libnetwork/drivers/remote/api"
	lnTypes "github.com/docker/libnetwork/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-docker-driver")

const (
	// ContainerInterfacePrefix is the container's internal interface name prefix.
	ContainerInterfacePrefix = "cilium"
)

// Driver interface that listens for docker requests.
type Driver interface {
	Listen(string) error
}

type driver struct {
	mutex       lock.RWMutex
	client      *client.Client
	conf        models.DaemonConfigurationStatus
	routes      []api.StaticRoute
	gatewayIPv6 string
	gatewayIPv4 string
}

func endpointID(id string) string {
	return endpointIDPkg.NewID(endpointIDPkg.DockerEndpointPrefix, id)
}

func newLibnetworkRoute(route route.Route) api.StaticRoute {
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

// NewDriver creates and returns a new Driver for the given API URL.
// If url is nil then use SockPath provided by CILIUM_SOCK
// or the cilium default SockPath
func NewDriver(url string) (Driver, error) {

	if url == "" {
		url = client.DefaultSockPath()
	}

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
			if res.Status.Addressing == nil || res.Status.Addressing.IPV6 == nil {
				scopedLog.Fatal("Invalid addressing information from daemon")
			}

			d.conf = *res.Status
			break
		}
	}

	if err := connector.SufficientAddressing(d.conf.Addressing); err != nil {
		scopedLog.WithError(err).Fatal("Insufficient addressing")
	}

	d.updateRoutes(nil)

	log.Infof("Cilium Docker plugin ready")

	return d, nil
}

func (driver *driver) updateRoutes(addressing *models.NodeAddressing) {
	driver.mutex.Lock()
	defer driver.mutex.Unlock()

	if addressing != nil {
		driver.conf.Addressing = addressing
	}

	driver.routes = []api.StaticRoute{}

	if driver.conf.Addressing.IPV6 != nil && driver.conf.Addressing.IPV6.Enabled {
		if routes, err := connector.IPv6Routes(driver.conf.Addressing, int(driver.conf.RouteMTU)); err != nil {
			log.Fatalf("Unable to generate IPv6 routes: %s", err)
		} else {
			for _, r := range routes {
				driver.routes = append(driver.routes, newLibnetworkRoute(r))
			}
		}

		driver.gatewayIPv6 = connector.IPv6Gateway(driver.conf.Addressing)
	}

	if driver.conf.Addressing.IPV4 != nil && driver.conf.Addressing.IPV4.Enabled {
		if routes, err := connector.IPv4Routes(driver.conf.Addressing, int(driver.conf.RouteMTU)); err != nil {
			log.Fatalf("Unable to generate IPv4 routes: %s", err)
		} else {
			for _, r := range routes {
				driver.routes = append(driver.routes, newLibnetworkRoute(r))
			}
		}

		driver.gatewayIPv4 = connector.IPv4Gateway(driver.conf.Addressing)
	}
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
	log.WithFields(logrus.Fields{
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
	var err error
	if err := json.NewDecoder(r.Body).Decode(&create); err != nil {
		sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.WithField(logfields.Request, logfields.Repr(&create)).Debug("Create endpoint request")

	if create.Interface.Address == "" && create.Interface.AddressIPv6 == "" {
		sendError(w, "No IPv4 or IPv6 address provided (required)", http.StatusBadRequest)
		return
	}

	endpoint := &models.EndpointChangeRequest{
		SyncBuildEndpoint: true,
		State:             models.EndpointStateWaitingForIdentity,
		DockerEndpointID:  create.EndpointID,
		DockerNetworkID:   create.NetworkID,
		Addressing: &models.AddressPair{
			IPV6: create.Interface.AddressIPv6,
			IPV4: create.Interface.Address,
		},
	}

	switch driver.conf.DatapathMode {
	case option.DatapathModeVeth:
		veth, _, _, err := connector.SetupVeth(create.EndpointID, int(driver.conf.DeviceMTU), endpoint)
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
	case option.DatapathModeIpvlan:
		ipvlan, _, _, err := connector.SetupIpvlan(
			create.EndpointID, int(driver.conf.DeviceMTU),
			int(driver.conf.IpvlanConfiguration.MasterDeviceIndex),
			driver.conf.IpvlanConfiguration.OperationMode, endpoint,
		)
		if err != nil {
			sendError(w, "Error while setting up ipvlan: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer func() {
			if err != nil {
				if err = netlink.LinkDel(ipvlan); err != nil {
					log.WithError(err).WithField(logfields.Ipvlan, ipvlan.Name).Warn("failed to clean up ipvlan")
				}
			}
		}()
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
	var ifName string
	if err := json.NewDecoder(r.Body).Decode(&del); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.WithField(logfields.Request, logfields.Repr(&del)).Debug("Delete endpoint request")

	switch driver.conf.DatapathMode {
	case option.DatapathModeVeth:
		ifName = connector.Endpoint2IfName(del.EndpointID)
	case option.DatapathModeIpvlan:
		ifName = connector.Endpoint2TempIfName(del.EndpointID)
	}

	if err := link.DeleteByName(ifName); err != nil {
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

	driver.mutex.RLock()
	defer driver.mutex.RUnlock()

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

	res := &api.JoinResponse{
		InterfaceName: &api.InterfaceName{
			SrcName:   connector.Endpoint2TempIfName(j.EndpointID),
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
	// res.Gateway = connector.IPv4Gateway(addr)

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
