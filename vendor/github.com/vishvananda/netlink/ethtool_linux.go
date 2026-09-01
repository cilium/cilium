package netlink

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func (h *Handle) ethtoolRequest(command uint8, flags int, attrs []*nl.RtAttr) ([][]syscall.NetlinkRouteAttr, error) {
	family, err := h.GenlFamilyGet(nl.ETHTOOL_GENL_NAME)
	if err != nil {
		return nil, err
	}

	req := h.newNetlinkRequest(int(family.ID), flags)
	req.AddData(&nl.Genlmsg{
		Command: command,
		Version: nl.ETHTOOL_GENL_VERSION,
	})
	for _, attr := range attrs {
		req.AddData(attr)
	}

	msgs, executeErr := req.Execute(unix.NETLINK_GENERIC, 0)
	if executeErr != nil && !errors.Is(executeErr, ErrDumpInterrupted) {
		return nil, executeErr
	}

	parsed := make([][]syscall.NetlinkRouteAttr, 0, len(msgs))
	for _, msg := range msgs {
		if len(msg) < nl.SizeofGenlmsg {
			return nil, fmt.Errorf("netlink: short ethtool response: got %d bytes, want at least %d", len(msg), nl.SizeofGenlmsg)
		}
		attrs, err := nl.ParseRouteAttr(msg[nl.SizeofGenlmsg:])
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, attrs)
	}
	return parsed, executeErr
}

func newEthtoolHeader(attrType, ifIndex int) (*nl.RtAttr, error) {
	if ifIndex <= 0 || uint64(ifIndex) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("netlink: invalid interface index %d", ifIndex)
	}
	header := nl.NewRtAttr(unix.NLA_F_NESTED|attrType, nil)
	header.AddRtAttr(nl.ETHTOOL_A_HEADER_DEV_INDEX, nl.Uint32Attr(uint32(ifIndex)))
	return header, nil
}

func readEthtoolUint8(attr syscall.NetlinkRouteAttr) (uint8, error) {
	if len(attr.Value) != 1 {
		return 0, fmt.Errorf("netlink: ethtool attribute %d has %d bytes, want 1", attr.Attr.Type&nl.NLA_TYPE_MASK, len(attr.Value))
	}
	return attr.Value[0], nil
}

func readEthtoolUint32(attr syscall.NetlinkRouteAttr) (uint32, error) {
	if len(attr.Value) != 4 {
		return 0, fmt.Errorf("netlink: ethtool attribute %d has %d bytes, want 4", attr.Attr.Type&nl.NLA_TYPE_MASK, len(attr.Value))
	}
	return native.Uint32(attr.Value), nil
}
