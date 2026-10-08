//go:build linux
// +build linux

package genetlink

import (
	"errors"
	"fmt"
	"math"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// errInvalidFamilyVersion is returned when a family's version is greater
// than an 8-bit integer.
var errInvalidFamilyVersion = errors.New("invalid family version attribute")

// getFamily retrieves a generic netlink family with the specified name.
func (c *Conn) getFamily(name string) (Family, error) {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: unix.CTRL_ATTR_FAMILY_NAME,
		Data: nlenc.Bytes(name),
	}})
	if err != nil {
		return Family{}, err
	}

	req := Message{
		Header: Header{
			Command: unix.CTRL_CMD_GETFAMILY,
			// TODO(mdlayher): grab nlctrl version?
			Version: 1,
		},
		Data: b,
	}

	msgs, err := c.Execute(req, unix.GENL_ID_CTRL, netlink.Request)
	if err != nil {
		return Family{}, err
	}

	// TODO(mdlayher): consider interpreting generic netlink header values

	families, err := buildFamilies(msgs)
	if err != nil {
		return Family{}, err
	}
	if len(families) != 1 {
		// If this were to ever happen, netlink must be in a state where
		// its answers cannot be trusted
		panic(fmt.Sprintf("netlink returned multiple families for name: %q", name))
	}

	return families[0], nil
}

// listFamilies retrieves all registered generic netlink families.
func (c *Conn) listFamilies() ([]Family, error) {
	req := Message{
		Header: Header{
			Command: unix.CTRL_CMD_GETFAMILY,
			// TODO(mdlayher): grab nlctrl version?
			Version: 1,
		},
	}

	msgs, err := c.Execute(req, unix.GENL_ID_CTRL, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, err
	}

	return buildFamilies(msgs)
}

// buildFamilies builds a slice of Families by parsing attributes from the
// input Messages.
func buildFamilies(msgs []Message) ([]Family, error) {
	families := make([]Family, 0, len(msgs))
	for _, m := range msgs {
		f, err := parseFamily(m.Data)
		if err != nil {
			return nil, err
		}

		families = append(families, f)
	}

	return families, nil
}

// parseFamily decodes netlink attributes into a Family.
func parseFamily(b []byte) (Family, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return Family{}, err
	}

	var f Family
	for ad.Next() {
		switch ad.Type() {
		case unix.CTRL_ATTR_FAMILY_ID:
			f.ID = ad.Uint16()
		case unix.CTRL_ATTR_FAMILY_NAME:
			f.Name = ad.String()
		case unix.CTRL_ATTR_VERSION:
			v := ad.Uint32()
			if v > math.MaxUint8 {
				return Family{}, errInvalidFamilyVersion
			}

			f.Version = uint8(v)
		case unix.CTRL_ATTR_MCAST_GROUPS:
			ad.Nested(parseMulticastGroups(&f.Groups))
		}
	}

	if err := ad.Err(); err != nil {
		return Family{}, err
	}

	return f, nil
}

// parseMulticastGroups parses an array of multicast group nested attributes
// into a slice of MulticastGroups.
func parseMulticastGroups(groups *[]MulticastGroup) func(*netlink.AttributeDecoder) error {
	return func(ad *netlink.AttributeDecoder) error {
		*groups = make([]MulticastGroup, 0, ad.Len())
		for ad.Next() {
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				var g MulticastGroup
				for nad.Next() {
					switch nad.Type() {
					case unix.CTRL_ATTR_MCAST_GRP_NAME:
						g.Name = nad.String()
					case unix.CTRL_ATTR_MCAST_GRP_ID:
						g.ID = nad.Uint32()
					}
				}

				*groups = append(*groups, g)
				return nil
			})
		}

		return nil
	}
}
