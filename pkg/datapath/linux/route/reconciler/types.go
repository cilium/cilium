// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"
	"strconv"

	"go.yaml.in/yaml/v3"
)

type AdminDistance int

const (
	// AdminDistanceDefault is the default administrative distance for routes
	// emitted by Cilium itself.
	AdminDistanceDefault AdminDistance = 100
)

type RouteOwner struct {
	name string
}

var _ yaml.Unmarshaler = (*RouteOwner)(nil)

func (o *RouteOwner) UnmarshalYAML(value *yaml.Node) error {
	type routeOwner struct {
		Name string
	}

	var r routeOwner
	err := value.Decode(&r)
	o.name = r.Name
	return err
}

func (o *RouteOwner) String() string {
	return o.name
}

type TableID uint32

const (
	TableMain  TableID = 254
	TableLocal TableID = 255
)

var _ yaml.Unmarshaler = (*TableID)(nil)

func (t *TableID) UnmarshalYAML(value *yaml.Node) error {
	var tableName string
	if err := value.Decode(&tableName); err != nil {
		return err
	}

	if err := t.FromString(tableName); err != nil {
		return fmt.Errorf("failed to parse table ID %q: %w", tableName, err)
	}

	return nil
}

func (t *TableID) FromString(s string) error {
	switch s {
	case "main":
		*t = TableMain
	case "local":
		*t = TableLocal
	default:
		table, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid table ID %q: %w", s, err)
		}
		*t = TableID(table)
	}
	return nil
}

func (t TableID) String() string {
	switch t {
	case TableMain:
		return "main (" + strconv.Itoa(int(t)) + ")"
	case TableLocal:
		return "local (" + strconv.Itoa(int(t)) + ")"
	}

	return strconv.Itoa(int(t))
}

type Scope uint8

const (
	SCOPE_UNIVERSE Scope = 0
	SCOPE_SITE     Scope = 200
	SCOPE_LINK     Scope = 253
	SCOPE_HOST     Scope = 254
	SCOPE_NOWHERE  Scope = 255
)

var _ yaml.Unmarshaler = (*Scope)(nil)

func (s *Scope) UnmarshalYAML(value *yaml.Node) error {
	var scopeName string
	if err := value.Decode(&scopeName); err != nil {
		return err
	}

	if err := s.FromString(scopeName); err != nil {
		return fmt.Errorf("failed to parse scope %q: %w", scopeName, err)
	}

	return nil
}

func (s *Scope) FromString(scopeName string) error {
	switch scopeName {
	case "universe":
		*s = SCOPE_UNIVERSE
	case "site":
		*s = SCOPE_SITE
	case "link":
		*s = SCOPE_LINK
	case "host":
		*s = SCOPE_HOST
	case "nowhere":
		*s = SCOPE_NOWHERE
	default:
		scope, err := strconv.ParseUint(scopeName, 10, 8)
		if err != nil {
			return fmt.Errorf("invalid scope %q: %w", scopeName, err)
		}
		*s = Scope(scope)
	}
	return nil
}

func (s Scope) String() string {
	switch s {
	case SCOPE_UNIVERSE:
		return "universe"
	case SCOPE_SITE:
		return "site"
	case SCOPE_LINK:
		return "link"
	case SCOPE_HOST:
		return "host"
	case SCOPE_NOWHERE:
		return "nowhere"
	default:
		return "unknown (" + strconv.Itoa(int(s)) + ")"
	}
}

type Type uint8

const (
	RTN_UNSPEC Type = 0x0
	// a gateway or direct route
	RTN_UNICAST Type = 0x1
	// packets matching a local route are sent up the network stack as destined for the local host
	RTN_LOCAL Type = 0x2
	// a local broadcast route (sent as a broadcast)
	RTN_BROADCAST Type = 0x3
	// a local broadcast route (sent as a unicast)
	RTN_ANYCAST Type = 0x4
	// a multicast route
	RTN_MULTICAST Type = 0x5
	// packets matching a blackhole route are silently dropped
	RTN_BLACKHOLE Type = 0x6
	// packets matching an unreachable route are dropped and an ICMP unreachable message is sent
	RTN_UNREACHABLE Type = 0x7
	// packets matching a prohibited route are dropped and an ICMP administratively prohibited message is sent
	RTN_PROHIBIT Type = 0x8
	// packets matching a throw route cause a lookup error
	RTN_THROW Type = 0x9
	// stateless NAT route
	RTN_NAT Type = 0xa
)

var _ yaml.Unmarshaler = (*Type)(nil)

func (t *Type) UnmarshalYAML(value *yaml.Node) error {
	var typeName string
	if err := value.Decode(&typeName); err != nil {
		return err
	}

	if err := t.FromString(typeName); err != nil {
		return fmt.Errorf("failed to parse type %q: %w", typeName, err)
	}

	return nil
}

func (t *Type) FromString(typeName string) error {
	switch typeName {
	case "unspec":
		*t = RTN_UNSPEC
	case "unicast":
		*t = RTN_UNICAST
	case "local":
		*t = RTN_LOCAL
	case "broadcast":
		*t = RTN_BROADCAST
	case "anycast":
		*t = RTN_ANYCAST
	case "multicast":
		*t = RTN_MULTICAST
	case "blackhole":
		*t = RTN_BLACKHOLE
	case "unreachable":
		*t = RTN_UNREACHABLE
	case "prohibit":
		*t = RTN_PROHIBIT
	case "throw":
		*t = RTN_THROW
	case "nat":
		*t = RTN_NAT
	default:
		typeValue, err := strconv.ParseUint(typeName, 10, 8)
		if err != nil {
			return fmt.Errorf("invalid type %q: %w", typeName, err)
		}
		*t = Type(typeValue)
	}
	return nil
}

func (t Type) String() string {
	switch t {
	case RTN_UNSPEC:
		return "unspec"
	case RTN_UNICAST:
		return "unicast"
	case RTN_LOCAL:
		return "local"
	case RTN_BROADCAST:
		return "broadcast"
	case RTN_ANYCAST:
		return "anycast"
	case RTN_MULTICAST:
		return "multicast"
	case RTN_BLACKHOLE:
		return "blackhole"
	case RTN_UNREACHABLE:
		return "unreachable"
	case RTN_PROHIBIT:
		return "prohibit"
	case RTN_THROW:
		return "throw"
	case RTN_NAT:
		return "nat"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}
