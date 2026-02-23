//go:build !linux
// +build !linux

package netlink

func DevLinkGetDeviceList() ([]*DevlinkDevice, error) {
	return nil, ErrNotImplemented
}

func DevLinkGetDeviceByName(Bus string, Device string) (*DevlinkDevice, error) {
	return nil, ErrNotImplemented
}

func DevLinkSetEswitchMode(Dev *DevlinkDevice, NewMode string) error {
	return ErrNotImplemented
}

func DevLinkGetAllPortList() ([]*DevlinkPort, error) {
	return nil, ErrNotImplemented
}

func DevlinkGetDeviceResources(bus string, device string) (*DevlinkResources, error) {
	return nil, ErrNotImplemented
}

func DevlinkGetDeviceParams(bus string, device string) ([]*DevlinkParam, error) {
	return nil, ErrNotImplemented
}

func DevlinkGetDeviceParamByName(bus string, device string, param string) (*DevlinkParam, error) {
	return nil, ErrNotImplemented
}

func DevlinkSplitPort(port *DevlinkPort, count uint32) error {
	return ErrNotImplemented
}

func DevlinkUnsplitPort(port *DevlinkPort) error {
	return ErrNotImplemented
}

func DevlinkSetDeviceParam(bus string, device string, param string, cmode uint8, value interface{}) error {
	return ErrNotImplemented
}

func DevLinkGetPortByIndex(Bus string, Device string, PortIndex uint32) (*DevlinkPort, error) {
	return nil, ErrNotImplemented
}

func DevLinkPortAdd(Bus string, Device string, Flavour uint16, Attrs DevLinkPortAddAttrs) (*DevlinkPort, error) {
	return nil, ErrNotImplemented
}

func DevLinkPortDel(Bus string, Device string, PortIndex uint32) error {
	return ErrNotImplemented
}

func DevlinkPortFnSet(Bus string, Device string, PortIndex uint32, FnAttrs DevlinkPortFnSetAttrs) error {
	return ErrNotImplemented
}

func DevlinkGetDeviceInfoByName(Bus string, Device string) (*DevlinkDeviceInfo, error) {
	return nil, ErrNotImplemented
}

func DevlinkGetDeviceInfoByNameAsMap(Bus string, Device string) (map[string]string, error) {
	return nil, ErrNotImplemented
}
