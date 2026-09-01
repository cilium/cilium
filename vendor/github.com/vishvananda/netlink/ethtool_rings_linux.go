package netlink

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// NetDevTCPDataSplit describes whether a device places TCP headers and payload
// data in separate receive buffers.
type NetDevTCPDataSplit uint8

const (
	NetDevTCPDataSplitUnknown NetDevTCPDataSplit = iota
	NetDevTCPDataSplitDisabled
	NetDevTCPDataSplitEnabled
)

// NetDevRings contains the ring parameters reported by a netdevice.
type NetDevRings struct {
	RxMax      uint32
	RxMiniMax  uint32
	RxJumboMax uint32
	TxMax      uint32
	Rx         uint32
	RxMini     uint32
	RxJumbo    uint32
	Tx         uint32

	RxBufLen        uint32
	TCPDataSplit    NetDevTCPDataSplit
	CQESize         uint32
	TxPush          bool
	RxPush          bool
	TxPushBufLen    uint32
	TxPushBufLenMax uint32
	HDSThreshold    uint32
	HDSThresholdMax uint32
}

// NetDevRingsConfig describes a partial ring-parameter update. Nil fields are
// left unchanged.
type NetDevRingsConfig struct {
	Rx       *uint32
	RxMini   *uint32
	RxJumbo  *uint32
	Tx       *uint32
	RxBufLen *uint32

	TCPDataSplit *NetDevTCPDataSplit
	CQESize      *uint32
	TxPush       *bool
	RxPush       *bool
	TxPushBufLen *uint32
	HDSThreshold *uint32
}

func parseNetDevRings(attrs []syscall.NetlinkRouteAttr) (*NetDevRings, error) {
	rings := &NetDevRings{}
	for _, attr := range attrs {
		typeID := attr.Attr.Type & nl.NLA_TYPE_MASK
		switch typeID {
		case nl.ETHTOOL_A_RINGS_RX_MAX,
			nl.ETHTOOL_A_RINGS_RX_MINI_MAX,
			nl.ETHTOOL_A_RINGS_RX_JUMBO_MAX,
			nl.ETHTOOL_A_RINGS_TX_MAX,
			nl.ETHTOOL_A_RINGS_RX,
			nl.ETHTOOL_A_RINGS_RX_MINI,
			nl.ETHTOOL_A_RINGS_RX_JUMBO,
			nl.ETHTOOL_A_RINGS_TX,
			nl.ETHTOOL_A_RINGS_RX_BUF_LEN,
			nl.ETHTOOL_A_RINGS_CQE_SIZE,
			nl.ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN,
			nl.ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX,
			nl.ETHTOOL_A_RINGS_HDS_THRESH,
			nl.ETHTOOL_A_RINGS_HDS_THRESH_MAX:
			value, err := readEthtoolUint32(attr)
			if err != nil {
				return nil, err
			}
			switch typeID {
			case nl.ETHTOOL_A_RINGS_RX_MAX:
				rings.RxMax = value
			case nl.ETHTOOL_A_RINGS_RX_MINI_MAX:
				rings.RxMiniMax = value
			case nl.ETHTOOL_A_RINGS_RX_JUMBO_MAX:
				rings.RxJumboMax = value
			case nl.ETHTOOL_A_RINGS_TX_MAX:
				rings.TxMax = value
			case nl.ETHTOOL_A_RINGS_RX:
				rings.Rx = value
			case nl.ETHTOOL_A_RINGS_RX_MINI:
				rings.RxMini = value
			case nl.ETHTOOL_A_RINGS_RX_JUMBO:
				rings.RxJumbo = value
			case nl.ETHTOOL_A_RINGS_TX:
				rings.Tx = value
			case nl.ETHTOOL_A_RINGS_RX_BUF_LEN:
				rings.RxBufLen = value
			case nl.ETHTOOL_A_RINGS_CQE_SIZE:
				rings.CQESize = value
			case nl.ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN:
				rings.TxPushBufLen = value
			case nl.ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX:
				rings.TxPushBufLenMax = value
			case nl.ETHTOOL_A_RINGS_HDS_THRESH:
				rings.HDSThreshold = value
			case nl.ETHTOOL_A_RINGS_HDS_THRESH_MAX:
				rings.HDSThresholdMax = value
			}
		case nl.ETHTOOL_A_RINGS_TCP_DATA_SPLIT,
			nl.ETHTOOL_A_RINGS_TX_PUSH,
			nl.ETHTOOL_A_RINGS_RX_PUSH:
			value, err := readEthtoolUint8(attr)
			if err != nil {
				return nil, err
			}
			switch typeID {
			case nl.ETHTOOL_A_RINGS_TCP_DATA_SPLIT:
				rings.TCPDataSplit = NetDevTCPDataSplit(value)
			case nl.ETHTOOL_A_RINGS_TX_PUSH:
				rings.TxPush = value != 0
			case nl.ETHTOOL_A_RINGS_RX_PUSH:
				rings.RxPush = value != 0
			}
		}
	}
	return rings, nil
}

// NetDevRingsGet returns the ring parameters for ifIndex.
func NetDevRingsGet(ifIndex int) (*NetDevRings, error) {
	return pkgHandle().NetDevRingsGet(ifIndex)
}

// NetDevRingsGet returns the ring parameters for ifIndex.
func (h *Handle) NetDevRingsGet(ifIndex int) (*NetDevRings, error) {
	header, err := newEthtoolHeader(nl.ETHTOOL_A_RINGS_HEADER, ifIndex)
	if err != nil {
		return nil, err
	}
	msgs, err := h.ethtoolRequest(nl.ETHTOOL_MSG_RINGS_GET, unix.NLM_F_ACK, []*nl.RtAttr{header})
	if err != nil {
		return nil, err
	}
	if len(msgs) != 1 {
		return nil, fmt.Errorf("netlink: expected one ethtool rings response, got %d", len(msgs))
	}
	return parseNetDevRings(msgs[0])
}

func newNetDevRingsSetAttrs(ifIndex int, config NetDevRingsConfig) ([]*nl.RtAttr, error) {
	header, err := newEthtoolHeader(nl.ETHTOOL_A_RINGS_HEADER, ifIndex)
	if err != nil {
		return nil, err
	}
	attrs := []*nl.RtAttr{header}
	addUint32 := func(attrType int, value *uint32) {
		if value != nil {
			attrs = append(attrs, nl.NewRtAttr(attrType, nl.Uint32Attr(*value)))
		}
	}
	addBool := func(attrType int, value *bool) {
		if value != nil {
			v := byte(0)
			if *value {
				v = 1
			}
			attrs = append(attrs, nl.NewRtAttr(attrType, []byte{v}))
		}
	}

	if config.RxBufLen != nil && *config.RxBufLen == 0 {
		return nil, fmt.Errorf("netlink: RX buffer length must not be zero")
	}
	if config.CQESize != nil && *config.CQESize == 0 {
		return nil, fmt.Errorf("netlink: CQE size must not be zero")
	}
	addUint32(nl.ETHTOOL_A_RINGS_RX, config.Rx)
	addUint32(nl.ETHTOOL_A_RINGS_RX_MINI, config.RxMini)
	addUint32(nl.ETHTOOL_A_RINGS_RX_JUMBO, config.RxJumbo)
	addUint32(nl.ETHTOOL_A_RINGS_TX, config.Tx)
	addUint32(nl.ETHTOOL_A_RINGS_RX_BUF_LEN, config.RxBufLen)
	if config.TCPDataSplit != nil {
		if *config.TCPDataSplit > NetDevTCPDataSplitEnabled {
			return nil, fmt.Errorf("netlink: invalid TCP data split value %d", *config.TCPDataSplit)
		}
		attrs = append(attrs, nl.NewRtAttr(nl.ETHTOOL_A_RINGS_TCP_DATA_SPLIT, []byte{byte(*config.TCPDataSplit)}))
	}
	addUint32(nl.ETHTOOL_A_RINGS_CQE_SIZE, config.CQESize)
	addBool(nl.ETHTOOL_A_RINGS_TX_PUSH, config.TxPush)
	addBool(nl.ETHTOOL_A_RINGS_RX_PUSH, config.RxPush)
	addUint32(nl.ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN, config.TxPushBufLen)
	addUint32(nl.ETHTOOL_A_RINGS_HDS_THRESH, config.HDSThreshold)
	return attrs, nil
}

// NetDevRingsSet applies a partial ring-parameter update to ifIndex.
func NetDevRingsSet(ifIndex int, config NetDevRingsConfig) error {
	return pkgHandle().NetDevRingsSet(ifIndex, config)
}

// NetDevRingsSet applies a partial ring-parameter update to ifIndex.
func (h *Handle) NetDevRingsSet(ifIndex int, config NetDevRingsConfig) error {
	attrs, err := newNetDevRingsSetAttrs(ifIndex, config)
	if err != nil {
		return err
	}
	_, err = h.ethtoolRequest(nl.ETHTOOL_MSG_RINGS_SET, unix.NLM_F_ACK, attrs)
	return err
}
