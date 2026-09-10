package netlink

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// NetDevRSSHashFunction identifies an RSS hash function.
type NetDevRSSHashFunction uint32

const (
	NetDevRSSHashFunctionToeplitz NetDevRSSHashFunction = 1 << iota
	NetDevRSSHashFunctionXOR
	NetDevRSSHashFunctionCRC32
)

// NetDevRSSInputTransformation identifies a transformation applied to RSS
// input fields before hashing.
type NetDevRSSInputTransformation uint32

const (
	NetDevRSSInputTransformationNone NetDevRSSInputTransformation = iota
	NetDevRSSInputTransformationSymmetricXOR
	NetDevRSSInputTransformationSymmetricORXOR
)

// NetDevRSS contains the RSS configuration for one context. Context zero is
// the main RSS context used for normal receive-side scaling.
type NetDevRSS struct {
	Context             uint32
	HashFunction        NetDevRSSHashFunction
	IndirectionTable    []uint32
	HashKey             []byte
	InputTransformation NetDevRSSInputTransformation
}

// NetDevRSSConfig describes a partial update to an existing RSS context. Nil
// fields are left unchanged. A non-nil, empty IndirectionTable resets the main
// context's table to its default; the kernel does not allow that operation for
// additional contexts.
type NetDevRSSConfig struct {
	HashFunction        *NetDevRSSHashFunction
	IndirectionTable    []uint32
	HashKey             []byte
	InputTransformation *NetDevRSSInputTransformation
}

const maxEthtoolAttrPayload = int(^uint16(0)) - unix.SizeofRtAttr

func parseNetDevRSS(attrs []syscall.NetlinkRouteAttr, context uint32) (*NetDevRSS, error) {
	rss := &NetDevRSS{Context: context}
	for _, attr := range attrs {
		typeID := attr.Attr.Type & nl.NLA_TYPE_MASK
		switch typeID {
		case nl.ETHTOOL_A_RSS_CONTEXT,
			nl.ETHTOOL_A_RSS_HFUNC,
			nl.ETHTOOL_A_RSS_INPUT_XFRM:
			value, err := readEthtoolUint32(attr)
			if err != nil {
				return nil, err
			}
			switch typeID {
			case nl.ETHTOOL_A_RSS_CONTEXT:
				if value != context {
					return nil, fmt.Errorf("netlink: ethtool RSS response context is %d, want %d", value, context)
				}
			case nl.ETHTOOL_A_RSS_HFUNC:
				rss.HashFunction = NetDevRSSHashFunction(value)
			case nl.ETHTOOL_A_RSS_INPUT_XFRM:
				rss.InputTransformation = NetDevRSSInputTransformation(value)
			}
		case nl.ETHTOOL_A_RSS_INDIR:
			if len(attr.Value)%4 != 0 {
				return nil, fmt.Errorf("netlink: RSS indirection table has %d bytes, want a multiple of 4", len(attr.Value))
			}
			rss.IndirectionTable = make([]uint32, len(attr.Value)/4)
			for i := range rss.IndirectionTable {
				rss.IndirectionTable[i] = native.Uint32(attr.Value[i*4:])
			}
		case nl.ETHTOOL_A_RSS_HKEY:
			rss.HashKey = append([]byte(nil), attr.Value...)
		}
	}
	return rss, nil
}

// NetDevRSSGet returns the RSS configuration for an existing context on
// ifIndex. Context zero selects the main RSS context.
func NetDevRSSGet(ifIndex int, context uint32) (*NetDevRSS, error) {
	return pkgHandle().NetDevRSSGet(ifIndex, context)
}

// NetDevRSSGet returns the RSS configuration for an existing context on
// ifIndex. Context zero selects the main RSS context.
func (h *Handle) NetDevRSSGet(ifIndex int, context uint32) (*NetDevRSS, error) {
	header, err := newEthtoolHeader(nl.ETHTOOL_A_RSS_HEADER, ifIndex)
	if err != nil {
		return nil, err
	}
	attrs := []*nl.RtAttr{header}
	if context != 0 {
		attrs = append(attrs, nl.NewRtAttr(nl.ETHTOOL_A_RSS_CONTEXT, nl.Uint32Attr(context)))
	}
	msgs, err := h.ethtoolRequest(nl.ETHTOOL_MSG_RSS_GET, unix.NLM_F_ACK, attrs)
	if err != nil {
		return nil, err
	}
	if len(msgs) != 1 {
		return nil, fmt.Errorf("netlink: expected one ethtool RSS response, got %d", len(msgs))
	}
	return parseNetDevRSS(msgs[0], context)
}

func encodeNetDevRSSIndirectionTable(table []uint32) ([]byte, error) {
	if len(table) > maxEthtoolAttrPayload/4 {
		return nil, fmt.Errorf("netlink: RSS indirection table has %d entries, maximum is %d", len(table), maxEthtoolAttrPayload/4)
	}
	data := make([]byte, len(table)*4)
	for i, queue := range table {
		native.PutUint32(data[i*4:], queue)
	}
	return data, nil
}

func newNetDevRSSSetAttrs(ifIndex int, context uint32, config NetDevRSSConfig) ([]*nl.RtAttr, error) {
	header, err := newEthtoolHeader(nl.ETHTOOL_A_RSS_HEADER, ifIndex)
	if err != nil {
		return nil, err
	}
	attrs := []*nl.RtAttr{header}
	if context != 0 {
		attrs = append(attrs, nl.NewRtAttr(nl.ETHTOOL_A_RSS_CONTEXT, nl.Uint32Attr(context)))
	}
	if config.HashFunction != nil {
		hashFunction := uint32(*config.HashFunction)
		switch *config.HashFunction {
		case NetDevRSSHashFunctionToeplitz,
			NetDevRSSHashFunctionXOR,
			NetDevRSSHashFunctionCRC32:
		default:
			return nil, fmt.Errorf("netlink: invalid RSS hash function %#x", *config.HashFunction)
		}
		attrs = append(attrs, nl.NewRtAttr(nl.ETHTOOL_A_RSS_HFUNC, nl.Uint32Attr(hashFunction)))
	}
	if config.IndirectionTable != nil {
		if context != 0 && len(config.IndirectionTable) == 0 {
			return nil, fmt.Errorf("netlink: cannot reset the indirection table for RSS context %d", context)
		}
		data, err := encodeNetDevRSSIndirectionTable(config.IndirectionTable)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nl.NewRtAttr(nl.ETHTOOL_A_RSS_INDIR, data))
	}
	if config.HashKey != nil {
		if len(config.HashKey) == 0 {
			return nil, fmt.Errorf("netlink: RSS hash key must not be empty")
		}
		if len(config.HashKey) > maxEthtoolAttrPayload {
			return nil, fmt.Errorf("netlink: RSS hash key has %d bytes, maximum is %d", len(config.HashKey), maxEthtoolAttrPayload)
		}
		attrs = append(attrs, nl.NewRtAttr(nl.ETHTOOL_A_RSS_HKEY, append([]byte(nil), config.HashKey...)))
	}
	if config.InputTransformation != nil {
		if *config.InputTransformation > NetDevRSSInputTransformationSymmetricORXOR {
			return nil, fmt.Errorf("netlink: invalid RSS input transformation %#x", *config.InputTransformation)
		}
		attrs = append(attrs, nl.NewRtAttr(nl.ETHTOOL_A_RSS_INPUT_XFRM, nl.Uint32Attr(uint32(*config.InputTransformation))))
	}
	return attrs, nil
}

// NetDevRSSSet applies a partial update to an existing RSS context on ifIndex.
// Context zero selects the main RSS context.
func NetDevRSSSet(ifIndex int, context uint32, config NetDevRSSConfig) error {
	return pkgHandle().NetDevRSSSet(ifIndex, context, config)
}

// NetDevRSSSet applies a partial update to an existing RSS context on ifIndex.
// Context zero selects the main RSS context.
func (h *Handle) NetDevRSSSet(ifIndex int, context uint32, config NetDevRSSConfig) error {
	attrs, err := newNetDevRSSSetAttrs(ifIndex, context, config)
	if err != nil {
		return err
	}
	_, err = h.ethtoolRequest(nl.ETHTOOL_MSG_RSS_SET, unix.NLM_F_ACK, attrs)
	return err
}
