package netlink

import (
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

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

func parseDevLinkDeviceList(msgs [][]byte) ([]*DevlinkDevice, error) {
	devices := make([]*DevlinkDevice, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := nl.ParseRouteAttr(m[nl.SizeofGenlmsg:])
		if err != nil {
			return nil, err
		}
		dev := &DevlinkDevice{}
		if err = dev.parseAttributes(attrs); err != nil {
			return nil, err
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

func parseEswitchMode(mode uint16) string {
	var eswitchMode = map[uint16]string{
		nl.DEVLINK_ESWITCH_MODE_LEGACY:    "legacy",
		nl.DEVLINK_ESWITCH_MODE_SWITCHDEV: "switchdev",
	}
	if eswitchMode[mode] == "" {
		return "unknown"
	} else {
		return eswitchMode[mode]
	}
}

func parseEswitchInlineMode(inlinemode uint8) string {
	var eswitchInlineMode = map[uint8]string{
		nl.DEVLINK_ESWITCH_INLINE_MODE_NONE:      "none",
		nl.DEVLINK_ESWITCH_INLINE_MODE_LINK:      "link",
		nl.DEVLINK_ESWITCH_INLINE_MODE_NETWORK:   "network",
		nl.DEVLINK_ESWITCH_INLINE_MODE_TRANSPORT: "transport",
	}
	if eswitchInlineMode[inlinemode] == "" {
		return "unknown"
	} else {
		return eswitchInlineMode[inlinemode]
	}
}

func parseEswitchEncapMode(encapmode uint8) string {
	var eswitchEncapMode = map[uint8]string{
		nl.DEVLINK_ESWITCH_ENCAP_MODE_NONE:  "disable",
		nl.DEVLINK_ESWITCH_ENCAP_MODE_BASIC: "enable",
	}
	if eswitchEncapMode[encapmode] == "" {
		return "unknown"
	} else {
		return eswitchEncapMode[encapmode]
	}
}

func (d *DevlinkDevice) parseAttributes(attrs []syscall.NetlinkRouteAttr) error {
	for _, a := range attrs {
		switch a.Attr.Type {
		case nl.DEVLINK_ATTR_BUS_NAME:
			d.BusName = string(a.Value)
		case nl.DEVLINK_ATTR_DEV_NAME:
			d.DeviceName = string(a.Value)
		case nl.DEVLINK_ATTR_ESWITCH_MODE:
			d.Attrs.Eswitch.Mode = parseEswitchMode(native.Uint16(a.Value))
		case nl.DEVLINK_ATTR_ESWITCH_INLINE_MODE:
			d.Attrs.Eswitch.InlineMode = parseEswitchInlineMode(uint8(a.Value[0]))
		case nl.DEVLINK_ATTR_ESWITCH_ENCAP_MODE:
			d.Attrs.Eswitch.EncapMode = parseEswitchEncapMode(uint8(a.Value[0]))
		}
	}
	return nil
}

func (dev *DevlinkDevice) parseEswitchAttrs(msgs [][]byte) {
	m := msgs[0]
	attrs, err := nl.ParseRouteAttr(m[nl.SizeofGenlmsg:])
	if err != nil {
		return
	}
	dev.parseAttributes(attrs)
}

func (h *Handle) getEswitchAttrs(family *GenlFamily, dev *DevlinkDevice) {
	msg := &nl.Genlmsg{
		Command: nl.DEVLINK_CMD_ESWITCH_GET,
		Version: nl.GENL_DEVLINK_VERSION,
	}
	req := h.newNetlinkRequest(int(family.ID), unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	req.AddData(msg)

	b := make([]byte, len(dev.BusName))
	copy(b, dev.BusName)
	data := nl.NewRtAttr(nl.DEVLINK_ATTR_BUS_NAME, b)
	req.AddData(data)

	b = make([]byte, len(dev.DeviceName))
	copy(b, dev.DeviceName)
	data = nl.NewRtAttr(nl.DEVLINK_ATTR_DEV_NAME, b)
	req.AddData(data)

	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return
	}
	dev.parseEswitchAttrs(msgs)
}

// DevLinkGetDeviceList provides a pointer to devlink devices and nil error,
// otherwise returns an error code.
func (h *Handle) DevLinkGetDeviceList() ([]*DevlinkDevice, error) {
	f, err := h.GenlFamilyGet(nl.GENL_DEVLINK_NAME)
	if err != nil {
		return nil, err
	}
	msg := &nl.Genlmsg{
		Command: nl.DEVLINK_CMD_GET,
		Version: nl.GENL_DEVLINK_VERSION,
	}
	req := h.newNetlinkRequest(int(f.ID),
		unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_DUMP)
	req.AddData(msg)
	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return nil, err
	}
	devices, err := parseDevLinkDeviceList(msgs)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		h.getEswitchAttrs(f, d)
	}
	return devices, nil
}

// DevLinkGetDeviceList provides a pointer to devlink devices and nil error,
// otherwise returns an error code.
func DevLinkGetDeviceList() ([]*DevlinkDevice, error) {
	return pkgHandle.DevLinkGetDeviceList()
}
