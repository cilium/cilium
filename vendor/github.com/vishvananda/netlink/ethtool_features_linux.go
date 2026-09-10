package netlink

import (
	"fmt"
	"sort"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// NetDevFeature contains the state of one netdevice feature.
type NetDevFeature struct {
	Hardware bool
	Wanted   bool
	Active   bool
	NoChange bool
}

func parseNetDevFeatureBitset(attr syscall.NetlinkRouteAttr) (map[string]bool, error) {
	attrs, err := nl.ParseRouteAttr(attr.Value)
	if err != nil {
		return nil, err
	}

	noMask := false
	var bits *syscall.NetlinkRouteAttr
	for i := range attrs {
		typeID := attrs[i].Attr.Type & nl.NLA_TYPE_MASK
		switch typeID {
		case nl.ETHTOOL_A_BITSET_NOMASK:
			if len(attrs[i].Value) != 0 {
				return nil, fmt.Errorf("netlink: ethtool bitset nomask flag has %d bytes, want 0", len(attrs[i].Value))
			}
			noMask = true
		case nl.ETHTOOL_A_BITSET_BITS:
			bits = &attrs[i]
		case nl.ETHTOOL_A_BITSET_VALUE, nl.ETHTOOL_A_BITSET_MASK:
			return nil, fmt.Errorf("netlink: compact ethtool feature bitset is not supported")
		}
	}
	if bits == nil {
		return nil, fmt.Errorf("netlink: ethtool feature bitset has no named bits")
	}

	entries, err := nl.ParseRouteAttr(bits.Value)
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.Attr.Type&nl.NLA_TYPE_MASK != nl.ETHTOOL_A_BITSET_BITS_BIT {
			continue
		}
		fields, err := nl.ParseRouteAttr(entry.Value)
		if err != nil {
			return nil, err
		}
		name := ""
		namePresent := false
		value := noMask
		for _, field := range fields {
			switch field.Attr.Type & nl.NLA_TYPE_MASK {
			case nl.ETHTOOL_A_BITSET_BIT_NAME:
				namePresent = true
				nameBytes := field.Value
				if len(nameBytes) != 0 && nameBytes[len(nameBytes)-1] == 0 {
					nameBytes = nameBytes[:len(nameBytes)-1]
				}
				if strings.IndexByte(string(nameBytes), 0) >= 0 {
					return nil, fmt.Errorf("netlink: malformed ethtool feature name %x", field.Value)
				}
				name = string(nameBytes)
			case nl.ETHTOOL_A_BITSET_BIT_VALUE:
				if len(field.Value) != 0 {
					return nil, fmt.Errorf("netlink: ethtool feature value flag has %d bytes, want 0", len(field.Value))
				}
				value = true
			}
		}
		if !namePresent {
			return nil, fmt.Errorf("netlink: ethtool feature bit has no name")
		}
		if name == "" {
			continue
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("netlink: duplicate ethtool feature %q", name)
		}
		result[name] = value
	}
	return result, nil
}

func parseNetDevFeatures(attrs []syscall.NetlinkRouteAttr) (map[string]NetDevFeature, error) {
	result := make(map[string]NetDevFeature)
	for _, attr := range attrs {
		typeID := attr.Attr.Type & nl.NLA_TYPE_MASK
		if typeID < nl.ETHTOOL_A_FEATURES_HW || typeID > nl.ETHTOOL_A_FEATURES_NOCHANGE {
			continue
		}
		values, err := parseNetDevFeatureBitset(attr)
		if err != nil {
			return nil, err
		}
		for name, value := range values {
			feature := result[name]
			switch typeID {
			case nl.ETHTOOL_A_FEATURES_HW:
				feature.Hardware = value
			case nl.ETHTOOL_A_FEATURES_WANTED:
				feature.Wanted = value
			case nl.ETHTOOL_A_FEATURES_ACTIVE:
				feature.Active = value
			case nl.ETHTOOL_A_FEATURES_NOCHANGE:
				feature.NoChange = value
			}
			result[name] = feature
		}
	}
	return result, nil
}

func netDevFeaturesSetError(unapplied map[string]bool) error {
	if len(unapplied) == 0 {
		return nil
	}

	names := make([]string, 0, len(unapplied))
	for name := range unapplied {
		names = append(names, name)
	}
	sort.Strings(names)
	changes := make([]string, 0, len(names))
	for _, name := range names {
		state := "off"
		if unapplied[name] {
			state = "on"
		}
		changes = append(changes, name+"="+state)
	}
	return fmt.Errorf("netlink: ethtool did not apply requested feature changes: %s", strings.Join(changes, ", "))
}

func verifyNetDevFeatureStates(config map[string]bool, features map[string]NetDevFeature) error {
	unapplied := make(map[string]bool)
	for name, requested := range config {
		feature, exists := features[name]
		if !exists || feature.Active != requested {
			unapplied[name] = requested
		}
	}
	return netDevFeaturesSetError(unapplied)
}

func parseNetDevFeaturesSetReply(attrs []syscall.NetlinkRouteAttr) error {
	var unapplied map[string]bool
	wantedSeen := false
	activeSeen := false
	for _, attr := range attrs {
		typeID := attr.Attr.Type & nl.NLA_TYPE_MASK
		switch typeID {
		case nl.ETHTOOL_A_FEATURES_WANTED:
			if wantedSeen {
				return fmt.Errorf("netlink: duplicate ethtool features set wanted bitset")
			}
			wantedSeen = true
			values, err := parseNetDevFeatureBitset(attr)
			if err != nil {
				return err
			}
			unapplied = values
		case nl.ETHTOOL_A_FEATURES_ACTIVE:
			if activeSeen {
				return fmt.Errorf("netlink: duplicate ethtool features set active bitset")
			}
			activeSeen = true
			if _, err := parseNetDevFeatureBitset(attr); err != nil {
				return err
			}
		}
	}
	if !wantedSeen {
		return fmt.Errorf("netlink: ethtool features set reply has no wanted bitset")
	}
	if !activeSeen {
		return fmt.Errorf("netlink: ethtool features set reply has no active bitset")
	}
	return netDevFeaturesSetError(unapplied)
}

// NetDevFeaturesGet returns the named feature states for ifIndex.
func NetDevFeaturesGet(ifIndex int) (map[string]NetDevFeature, error) {
	return pkgHandle().NetDevFeaturesGet(ifIndex)
}

// NetDevFeaturesGet returns the named feature states for ifIndex.
func (h *Handle) NetDevFeaturesGet(ifIndex int) (map[string]NetDevFeature, error) {
	header, err := newEthtoolHeader(nl.ETHTOOL_A_FEATURES_HEADER, ifIndex)
	if err != nil {
		return nil, err
	}
	msgs, err := h.ethtoolRequest(nl.ETHTOOL_MSG_FEATURES_GET, unix.NLM_F_ACK, []*nl.RtAttr{header})
	if err != nil {
		return nil, err
	}
	if len(msgs) != 1 {
		return nil, fmt.Errorf("netlink: expected one ethtool features response, got %d", len(msgs))
	}
	return parseNetDevFeatures(msgs[0])
}

func newNetDevFeaturesSetAttrs(ifIndex int, config map[string]bool) ([]*nl.RtAttr, error) {
	header, err := newEthtoolHeader(nl.ETHTOOL_A_FEATURES_HEADER, ifIndex)
	if err != nil {
		return nil, err
	}
	if len(config) == 0 {
		return nil, fmt.Errorf("netlink: ethtool feature configuration is empty")
	}

	names := make([]string, 0, len(config))
	for name := range config {
		if name == "" || strings.IndexByte(name, 0) >= 0 {
			return nil, fmt.Errorf("netlink: invalid ethtool feature name %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	wanted := nl.NewRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_FEATURES_WANTED, nil)
	bits := wanted.AddRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_BITSET_BITS, nil)
	for _, name := range names {
		bit := bits.AddRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_BITSET_BITS_BIT, nil)
		bit.AddRtAttr(nl.ETHTOOL_A_BITSET_BIT_NAME, nl.ZeroTerminated(name))
		if config[name] {
			bit.AddRtAttr(nl.ETHTOOL_A_BITSET_BIT_VALUE, nil)
		}
	}
	return []*nl.RtAttr{header, wanted}, nil
}

// NetDevFeaturesSet applies named feature changes to ifIndex. It returns an
// error if any requested state is not active. Features absent from config are
// left unchanged.
func NetDevFeaturesSet(ifIndex int, config map[string]bool) error {
	return pkgHandle().NetDevFeaturesSet(ifIndex, config)
}

// NetDevFeaturesSet applies named feature changes to ifIndex. It returns an
// error if any requested state is not active. Features absent from config are
// left unchanged.
func (h *Handle) NetDevFeaturesSet(ifIndex int, config map[string]bool) error {
	attrs, err := newNetDevFeaturesSetAttrs(ifIndex, config)
	if err != nil {
		return err
	}
	msgs, err := h.ethtoolRequest(nl.ETHTOOL_MSG_FEATURES_SET, unix.NLM_F_ACK, attrs)
	if err != nil {
		return err
	}
	switch len(msgs) {
	case 0:
		// Older kernels omit the reply when the wanted bitmap is unchanged.
		features, err := h.NetDevFeaturesGet(ifIndex)
		if err != nil {
			return fmt.Errorf("netlink: verify ethtool feature changes: %w", err)
		}
		return verifyNetDevFeatureStates(config, features)
	case 1:
		return parseNetDevFeaturesSetReply(msgs[0])
	default:
		return fmt.Errorf("netlink: expected at most one ethtool features set response, got %d", len(msgs))
	}
}
