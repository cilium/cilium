package driverapi

import (
	"net"

	"github.com/docker/libnetwork/discoverapi"
)

// NetworkPluginEndpointType represents the Endpoint Type used by Plugin system
const NetworkPluginEndpointType = "NetworkDriver"

// Driver is an interface that every plugin driver needs to implement.
type Driver interface {
	discoverapi.Discover

	// CreateNetwork invokes the driver method to create a network passing
	// the network id and network specific config. The config mechanism will
	// eventually be replaced with labels which are yet to be introduced.
	CreateNetwork(nid string, options map[string]interface{}, ipV4Data, ipV6Data []IPAMData) error

	// DeleteNetwork invokes the driver method to delete network passing
	// the network id.
	DeleteNetwork(nid string) error

	// CreateEndpoint invokes the driver method to create an endpoint
	// passing the network id, endpoint id endpoint information and driver
	// specific config. The endpoint information can be either consumed by
	// the driver or populated by the driver. The config mechanism will
	// eventually be replaced with labels which are yet to be introduced.
	CreateEndpoint(nid, eid string, ifInfo InterfaceInfo, options map[string]interface{}) error

	// DeleteEndpoint invokes the driver method to delete an endpoint
	// passing the network id and endpoint id.
	DeleteEndpoint(nid, eid string) error

	// EndpointOperInfo retrieves from the driver the operational data related to the specified endpoint
	EndpointOperInfo(nid, eid string) (map[string]interface{}, error)

	// Join method is invoked when a Sandbox is attached to an endpoint.
	Join(nid, eid string, sboxKey string, jinfo JoinInfo, options map[string]interface{}) error

	// Leave method is invoked when a Sandbox detaches from an endpoint.
	Leave(nid, eid string) error

	// ProgramExternalConnectivity invokes the driver method which does the necessary
	// programming to allow the external connectivity dictated by the passed options
	ProgramExternalConnectivity(nid, eid string, options map[string]interface{}) error

	// RevokeExternalConnectivity aks the driver to remove any external connectivity
	// programming that was done so far
	RevokeExternalConnectivity(nid, eid string) error

	// Type returns the the type of this driver, the network type this driver manages
	Type() string
}

// InterfaceInfo provides a go interface for drivers to retrive
// network information to interface resources.
type InterfaceInfo interface {
	// SetMacAddress allows the driver to set the mac address to the endpoint interface
	// during the call to CreateEndpoint, if the mac address is not already set.
	SetMacAddress(mac net.HardwareAddr) error

	// SetIPAddress allows the driver to set the ip address to the endpoint interface
	// during the call to CreateEndpoint, if the address is not already set.
	// The API is to be used to assign both the IPv4 and IPv6 address types.
	SetIPAddress(ip *net.IPNet) error

	// MacAddress returns the MAC address.
	MacAddress() net.HardwareAddr

	// Address returns the IPv4 address.
	Address() *net.IPNet

	// AddressIPv6 returns the IPv6 address.
	AddressIPv6() *net.IPNet
}

// InterfaceNameInfo provides a go interface for the drivers to assign names
// to interfaces.
type InterfaceNameInfo interface {
	// SetNames method assigns the srcName and dstPrefix for the interface.
	SetNames(srcName, dstPrefix string) error
}

// JoinInfo represents a set of resources that the driver has the ability to provide during
// join time.
type JoinInfo interface {
	// InterfaceName returns a InterfaceNameInfo go interface to facilitate
	// setting the names for the interface.
	InterfaceName() InterfaceNameInfo

	// SetGateway sets the default IPv4 gateway when a container joins the endpoint.
	SetGateway(net.IP) error

	// SetGatewayIPv6 sets the default IPv6 gateway when a container joins the endpoint.
	SetGatewayIPv6(net.IP) error

	// AddStaticRoute adds a route to the sandbox.
	// It may be used in addition to or instead of a default gateway (as above).
	AddStaticRoute(destination *net.IPNet, routeType int, nextHop net.IP) error

	// DisableGatewayService tells libnetwork not to provide Default GW for the container
	DisableGatewayService()
}

// DriverCallback provides a Callback interface for Drivers into LibNetwork
type DriverCallback interface {
	// RegisterDriver provides a way for Remote drivers to dynamically register new NetworkType and associate with a driver instance
	RegisterDriver(name string, driver Driver, capability Capability) error
}

// Capability represents the high level capabilities of the drivers which libnetwork can make use of
type Capability struct {
	DataScope string
}

// IPAMData represents the per-network ip related
// operational information libnetwork will send
// to the network driver during CreateNetwork()
type IPAMData struct {
	AddressSpace string
	Pool         *net.IPNet
	Gateway      *net.IPNet
	AuxAddresses map[string]*net.IPNet
}
