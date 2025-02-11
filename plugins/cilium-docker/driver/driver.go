// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	apiTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	dockerCliAPI "github.com/docker/docker/client"
	"github.com/docker/libnetwork/drivers/remote/api"
	lnTypes "github.com/docker/libnetwork/types"
	"github.com/gorilla/mux"
	"github.com/spf13/afero"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	endpointIDPkg "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.With(slog.String(logfields.LogSubsys, "cilium-docker-driver"))

var endpointIDRx = regexp.MustCompile(`\A[-.0-9a-z]+\z`)

// Driver interface that listens for docker requests.
type Driver interface {
	Listen(string) error
}

type driver struct {
	mutex        lock.RWMutex
	client       *client.Client
	dockerClient *dockerCliAPI.Client
	conf         models.DaemonConfigurationStatus
	routes       []api.StaticRoute
	gatewayIPv6  string
	gatewayIPv4  string
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
func NewDriver(ciliumSockPath, dockerHostPath string) (Driver, error) {

	if ciliumSockPath == "" {
		ciliumSockPath = client.DefaultSockPath()
	}

	c, err := client.NewClient(ciliumSockPath)
	if err != nil {
		logging.Fatal(
			log,
			"Error while starting cilium-client",
			slog.Any(logfields.Error, err),
			slog.String("ciliumSockPath", ciliumSockPath),
		)
	}

	dockerCli, err := dockerCliAPI.NewClientWithOpts(
		dockerCliAPI.WithHost(dockerHostPath),
		dockerCliAPI.WithAPIVersionNegotiation(),
	)
	if err != nil {
		logging.Fatal(
			log,
			"Error while starting cilium-client",
			slog.Any(logfields.Error, err),
			slog.String("ciliumSockPath", ciliumSockPath),
			slog.String("dockerHostPath", dockerHostPath),
		)
	}

	d := &driver{client: c, dockerClient: dockerCli}

	for tries := 0; tries < 24; tries++ {
		if res, err := c.ConfigGet(); err != nil {
			if tries == 23 {
				logging.Fatal(
					log,
					"Unable to connect to cilium daemon",
					slog.Any(logfields.Error, err),
					slog.String("ciliumSockPath", ciliumSockPath),
					slog.String("dockerHostPath", dockerHostPath),
				)
			} else {
				log.Info(
					"Waiting for cilium daemon to start up...",
					slog.String("ciliumSockPath", ciliumSockPath),
					slog.String("dockerHostPath", dockerHostPath),
				)
			}
			time.Sleep(time.Duration(tries) * time.Second)
		} else {
			if res.Status.Addressing == nil || (res.Status.Addressing.IPV4 == nil && res.Status.Addressing.IPV6 == nil) {
				logging.Fatal(
					log,
					"Invalid addressing information from daemon",
					slog.String("ciliumSockPath", ciliumSockPath),
					slog.String("dockerHostPath", dockerHostPath),
				)
			}

			d.conf = *res.Status
			break
		}
	}

	if err := connector.SufficientAddressing(d.conf.Addressing); err != nil {
		logging.Fatal(
			log,
			"Insufficient addressing",
			slog.Any(logfields.Error, err),
			slog.String("ciliumSockPath", ciliumSockPath),
			slog.String("dockerHostPath", dockerHostPath),
		)
	}

	d.updateRoutes(nil)

	log.Info("Starting docker events watcher")

	go func() {
		eventsCh, errCh := dockerCli.Events(context.Background(), apiTypes.EventsOptions{})
		for {
			select {
			case err := <-errCh:
				log.Error("Unable to connect to docker events channel, reconnecting...", slog.Any(logfields.Error, err))
				time.Sleep(5 * time.Second)
				eventsCh, errCh = dockerCli.Events(context.Background(), apiTypes.EventsOptions{})
			case event := <-eventsCh:
				if event.Type != events.ContainerEventType || event.Action != "start" {
					break
				}
				d.updateCiliumEP(event)
			}
		}
	}()

	log.Info("Cilium Docker plugin ready",
		slog.String("ciliumSockPath", ciliumSockPath),
		slog.String("dockerHostPath", dockerHostPath),
	)

	return d, nil
}

func (driver *driver) updateCiliumEP(event events.Message) {
	logAttr := slog.Any("event", event)
	cont, err := driver.dockerClient.ContainerInspect(context.Background(), event.Actor.ID)
	if err != nil {
		log.Error(
			"Unable to inspect container",
			slog.Any(logfields.Error, err),
			slog.String(logfields.ContainerID, event.Actor.ID),
			logAttr,
		)
	}
	if cont.Config == nil || cont.NetworkSettings == nil {
		return
	}
	var epID string
	for _, network := range cont.NetworkSettings.Networks {
		epID = network.EndpointID
		break
	}
	if epID == "" {
		return
	}
	img, _, err := driver.dockerClient.ImageInspectWithRaw(context.Background(), cont.Config.Image)
	if err != nil {
		log.Error(
			"Unable to inspect image",
			slog.Any(logfields.Error, err),
			slog.String("image-id", cont.Config.Image),
			logAttr,
		)
	}
	lbls := cont.Config.Labels
	if img.Config != nil && img.Config.Labels != nil {
		lbls = img.Config.Labels
		// container labels overwrite image labels
		for k, v := range cont.Config.Labels {
			lbls[k] = v
		}
	}
	addLbls := labels.Map2Labels(lbls, labels.LabelSourceContainer).GetModel()
	ecr := &models.EndpointChangeRequest{
		ContainerID:   event.Actor.ID,
		ContainerName: strings.TrimPrefix(cont.Name, "/"),
		Labels:        addLbls,
		State:         models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}
	err = driver.client.EndpointPatch(endpointID(epID), ecr)
	if err != nil {
		log.Error(
			"Error while patching the endpoint labels of container",
			slog.Any(logfields.Error, err),
			slog.String(logfields.ContainerID, event.Actor.ID),
			slog.String(logfields.EndpointID, epID),
			slog.Any(logfields.Labels, cont.Config.Labels),
			logAttr,
		)
	}
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
			logging.Fatal(log, "Unable to generate IPv6 routes", slog.Any(logfields.Error, err))
		} else {
			for _, r := range routes {
				driver.routes = append(driver.routes, newLibnetworkRoute(r))
			}
		}

		driver.gatewayIPv6 = connector.IPv6Gateway(driver.conf.Addressing)
	}

	if driver.conf.Addressing.IPV4 != nil && driver.conf.Addressing.IPV4.Enabled {
		if routes, err := connector.IPv4Routes(driver.conf.Addressing, int(driver.conf.RouteMTU)); err != nil {
			logging.Fatal(log, "Unable to generate IPv4 routes", slog.Any(logfields.Error, err))
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
	log.Warn(
		"plugin Not found",
		slog.Any(logfields.Object, r),
	)
	http.NotFound(w, r)
}

func sendError(w http.ResponseWriter, msg string, code int) {
	log.Error(
		"Sending error",
		slog.Any("code", code),
		slog.Any("msg", msg),
	)
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
		logging.Fatal(log, "handshake encode", slog.Any(logfields.Error, err))
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
		logging.Fatal(log, "capabilities encode", slog.Any(logfields.Error, err))
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
	log.Debug(
		"Network Create Called",
		slog.Any(logfields.Request, create),
	)
	emptyResponse(w)
}

func (driver *driver) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	var delete api.DeleteNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&delete); err != nil {
		sendError(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Debug(
		"Delete network request",
		slog.Any(logfields.Request, delete),
	)
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
	log.Debug(
		"Create endpoint request",
		slog.Any(logfields.Request, create),
	)

	if create.Interface.Address == "" && create.Interface.AddressIPv6 == "" {
		sendError(w, "No IPv4 or IPv6 address provided (required)", http.StatusBadRequest)
		return
	}
	if !endpointIDRx.MatchString(create.EndpointID) {
		sendError(w, "Invalid endpoint ID", http.StatusBadRequest)
		return
	}

	endpoint := &models.EndpointChangeRequest{
		SyncBuildEndpoint: true,
		State:             models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		DockerEndpointID:  create.EndpointID,
		DockerNetworkID:   create.NetworkID,
		Addressing: &models.AddressPair{
			IPV6: create.Interface.AddressIPv6,
			IPV4: create.Interface.Address,
		},
	}

	removeLinkOnErr := func(link netlink.Link) {
		if err != nil && link != nil && !reflect.ValueOf(link).IsNil() {
			if err := netlink.LinkDel(link); err != nil {
				log.Warn(
					"failed to clean up",
					slog.Any(logfields.Error, err),
					slog.Any(logfields.DatapathMode, driver.conf.DatapathMode),
					slog.String(logfields.Device, link.Attrs().Name),
				)
			}
		}
	}

	switch driver.conf.DatapathMode {
	case datapathOption.DatapathModeVeth:
		var veth *netlink.Veth
		veth, _, _, err = connector.SetupVeth(create.EndpointID, int(driver.conf.DeviceMTU),
			int(driver.conf.GROMaxSize), int(driver.conf.GSOMaxSize),
			int(driver.conf.GROIPV4MaxSize), int(driver.conf.GSOIPV4MaxSize), endpoint, sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"))
		defer removeLinkOnErr(veth)
	}
	if err != nil {
		sendError(w,
			fmt.Sprintf("Error while setting up %s mode: %s", driver.conf.DatapathMode, err),
			http.StatusBadRequest)
		return
	}

	// FIXME: Translate port mappings to RuleL4 policy elements

	if _, err = driver.client.EndpointCreate(endpoint); err != nil {
		sendError(w, fmt.Sprintf("Error creating endpoint %s", err), http.StatusBadRequest)
		return
	}

	log.Debug(
		"Created new endpoint",
		slog.Any(logfields.EndpointID, create.EndpointID),
	)

	respIface := &api.EndpointInterface{
		// Fixme: the lxcmac is an empty string at this point and we only know the
		// mac address at the end of joinEndpoint
		// There's no problem in the setup but docker inspect will show an empty mac address
		MacAddress: "",
	}

	resp := &api.CreateEndpointResponse{
		Interface: respIface,
	}
	log.Debug(
		"Create endpoint response",
		slog.Any(logfields.Response, resp),
	)
	objectResponse(w, resp)
}

func (driver *driver) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var del api.DeleteEndpointRequest
	var ifName string
	if err := json.NewDecoder(r.Body).Decode(&del); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debug(
		"Delete endpoint request",
		slog.Any(logfields.Response, del),
	)

	switch driver.conf.DatapathMode {
	case datapathOption.DatapathModeVeth:
		ifName = connector.Endpoint2IfName(del.EndpointID)
	}

	if err := link.DeleteByName(ifName); err != nil {
		log.Warn("Error while deleting link", slog.Any(logfields.Error, err))
	}

	emptyResponse(w)
}

func (driver *driver) infoEndpoint(w http.ResponseWriter, r *http.Request) {
	var info api.EndpointInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debug(
		"Endpoint info request",
		slog.Any(logfields.Request, info),
	)
	objectResponse(w, &api.EndpointInfoResponse{Value: map[string]interface{}{}})
	log.Debug(
		"Endpoint info",
		slog.String(logfields.Response, info.EndpointID),
	)
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
	log.Debug(
		"Join request",
		slog.Any(logfields.Request, j),
	)

	old, err := driver.client.EndpointGet(endpointID(j.EndpointID))
	if err != nil {
		sendError(w, fmt.Sprintf("Error retrieving endpoint %s", err), http.StatusBadRequest)
		return
	}

	log.Debug(
		"Existing endpoint",
		slog.Any(logfields.Object, old),
	)

	res := &api.JoinResponse{
		InterfaceName: &api.InterfaceName{
			SrcName:   connector.Endpoint2TempIfName(j.EndpointID),
			DstPrefix: connector.ContainerInterfacePrefix,
		},
		StaticRoutes:          driver.routes,
		DisableGatewayService: true,
		GatewayIPv6:           driver.gatewayIPv6,
		// GatewayIPv4:           driver.gatewayIPv4,
	}

	// FIXME? Having the following code results on a runtime error: docker: Error
	// response from daemon: oci runtime error: process_linux.go:334: running prestart
	// hook 0 caused "exit status 1: time=\"2016-10-26T06:33:17-07:00\" level=fatal
	// msg=\"failed to set gateway while updating gateway: file exists\" \n"
	//
	// If empty, it works as expected without docker runtime errors
	// res.Gateway = connector.IPv4Gateway(addr)

	log.Debug(
		"Join response",
		slog.Any(logfields.Response, res),
	)
	objectResponse(w, res)
}

func (driver *driver) leaveEndpoint(w http.ResponseWriter, r *http.Request) {
	var l api.LeaveRequest
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}
	log.Debug(
		"Leave request",
		slog.Any(logfields.Request, l),
	)

	if err := driver.client.EndpointDelete(endpointID(l.EndpointID)); err != nil {
		log.Warn("Leaving the endpoint failed", slog.Any(logfields.Error, err))
	}

	emptyResponse(w)
}
