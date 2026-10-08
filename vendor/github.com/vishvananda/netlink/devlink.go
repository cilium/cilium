package netlink

import "net"

// DevlinkDevEswitchAttr represents device's eswitch attributes
type DevlinkDevEswitchAttr struct {
	Mode       string
	InlineMode string
	EncapMode  string
}

// DevlinkDevAttrs represents device attributes
type DevlinkDevAttrs struct {
	Eswitch DevlinkDevEswitchAttr
}

// DevlinkDevice represents device and its attributes
type DevlinkDevice struct {
	BusName    string
	DeviceName string
	Attrs      DevlinkDevAttrs
}

// DevlinkPortFn represents port function and its attributes
type DevlinkPortFn struct {
	HwAddr  net.HardwareAddr
	State   uint8
	OpState uint8
}

// DevlinkPortFnSetAttrs represents attributes to set
type DevlinkPortFnSetAttrs struct {
	FnAttrs     DevlinkPortFn
	HwAddrValid bool
	StateValid  bool
}

// DevlinkPort represents port and its attributes
type DevlinkPort struct {
	BusName          string
	DeviceName       string
	PortIndex        uint32
	PortType         uint16
	NetdeviceName    string
	NetdevIfIndex    uint32
	RdmaDeviceName   string
	PortFlavour      uint16
	Fn               *DevlinkPortFn
	PortNumber       *uint32
	PfNumber         *uint16
	VfNumber         *uint16
	SfNumber         *uint32
	ControllerNumber *uint32
	External         *bool
}

type DevLinkPortAddAttrs struct {
	Controller      uint32
	SfNumber        uint32
	PortIndex       uint32
	PfNumber        uint16
	SfNumberValid   bool
	PortIndexValid  bool
	ControllerValid bool
}

// DevlinkDeviceInfo represents devlink info
type DevlinkDeviceInfo struct {
	Driver         string
	SerialNumber   string
	BoardID        string
	FwApp          string
	FwAppBoundleID string
	FwAppName      string
	FwBoundleID    string
	FwMgmt         string
	FwMgmtAPI      string
	FwMgmtBuild    string
	FwNetlist      string
	FwNetlistBuild string
	FwPsidAPI      string
	FwUndi         string
}

// DevlinkResource represents a device resource
type DevlinkResource struct {
	Name            string
	ID              uint64
	Size            uint64
	SizeNew         uint64
	SizeMin         uint64
	SizeMax         uint64
	SizeGranularity uint64
	PendingChange   bool
	Unit            uint8
	SizeValid       bool
	OCCValid        bool
	OCCSize         uint64
	Parent          *DevlinkResource
	Children        []DevlinkResource
}

// DevlinkResources represents all devlink resources of a devlink device
type DevlinkResources struct {
	Bus       string
	Device    string
	Resources []DevlinkResource
}

// DevlinkParam represents parameter of the device
type DevlinkParam struct {
	Name      string
	IsGeneric bool
	Type      uint8 // possible values are in nl.DEVLINK_PARAM_TYPE_* constants
	Values    []DevlinkParamValue
}

// DevlinkParamValue contains values of the parameter
// Data field contains specific type which can be casted by unsing info from the DevlinkParam.Type field
type DevlinkParamValue struct {
	rawData []byte
	Data    interface{}
	CMODE   uint8 // possible values are in nl.DEVLINK_PARAM_CMODE_* constants
}
