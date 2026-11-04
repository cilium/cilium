package netlink

import (
	"fmt"
	"net"
)

// Rule represents a netlink rule.
type Rule struct {
	Priority          int
	Family            int
	Table             int
	Mark              uint32
	Mask              *uint32
	Tos               uint
	TunID             uint
	Goto              int
	Src               *net.IPNet
	Dst               *net.IPNet
	Flow              int
	IifName           string
	OifName           string
	SuppressIfgroup   int
	SuppressPrefixlen int
	Invert            bool
	Dport             *RulePortRange
	Sport             *RulePortRange
	IPProto           int
	UIDRange          *RuleUIDRange
	Protocol          uint8
	Type              uint8
}

func (r Rule) Equal(x Rule) bool {
	return r.Table == x.Table &&
		((r.Src == nil && x.Src == nil) ||
			(r.Src != nil && x.Src != nil && r.Src.String() == x.Src.String())) &&
		((r.Dst == nil && x.Dst == nil) ||
			(r.Dst != nil && x.Dst != nil && r.Dst.String() == x.Dst.String())) &&
		r.OifName == x.OifName &&
		r.Priority == x.Priority &&
		r.Family == x.Family &&
		r.IifName == x.IifName &&
		r.Invert == x.Invert &&
		r.Tos == x.Tos &&
		r.Type == x.Type &&
		r.IPProto == x.IPProto &&
		r.Protocol == x.Protocol &&
		r.Mark == x.Mark &&
		// For non-zero marks, mask defaults to 0xFFFFFFFF if not set. So if either mask is nil
		// while the other is 0xFFFFFFFF when mark is non-zero, treat the masks as identical.
		// See kernel source: https://github.com/torvalds/linux/blob/v6.15/net/core/fib_rules.c#L624
		(ptrEqual(r.Mask, x.Mask) || (r.Mark != 0 &&
			(r.Mask == nil && *x.Mask == 0xFFFFFFFF || x.Mask == nil && *r.Mask == 0xFFFFFFFF))) &&
		r.TunID == x.TunID &&
		r.Goto == x.Goto &&
		r.Flow == x.Flow &&
		r.SuppressIfgroup == x.SuppressIfgroup &&
		r.SuppressPrefixlen == x.SuppressPrefixlen &&
		(r.Dport == x.Dport || (r.Dport != nil && x.Dport != nil && r.Dport.Equal(*x.Dport))) &&
		(r.Sport == x.Sport || (r.Sport != nil && x.Sport != nil && r.Sport.Equal(*x.Sport))) &&
		(r.UIDRange == x.UIDRange || (r.UIDRange != nil && x.UIDRange != nil && r.UIDRange.Equal(*x.UIDRange)))
}

func ptrEqual(a, b *uint32) bool {
	if a == b {
		return true
	}
	if (a == nil) || (b == nil) {
		return false
	}
	return *a == *b
}

func (r Rule) String() string {
	from := "all"
	if r.Src != nil && r.Src.String() != "<nil>" {
		from = r.Src.String()
	}

	to := "all"
	if r.Dst != nil && r.Dst.String() != "<nil>" {
		to = r.Dst.String()
	}

	return fmt.Sprintf("ip rule %d: from %s to %s table %d %s",
		r.Priority, from, to, r.Table, r.typeString())
}

// NewRule return empty rules.
func NewRule() *Rule {
	return &Rule{
		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Mark:              0,
		Mask:              nil,
		Goto:              -1,
		Flow:              -1,
	}
}

// NewRulePortRange creates rule sport/dport range.
func NewRulePortRange(start, end uint16) *RulePortRange {
	return &RulePortRange{Start: start, End: end}
}

// RulePortRange represents rule sport/dport range.
type RulePortRange struct {
	Start uint16
	End   uint16
}

func (r RulePortRange) Equal(x RulePortRange) bool {
	return r.Start == x.Start && r.End == x.End
}

// NewRuleUIDRange creates rule uid range.
func NewRuleUIDRange(start, end uint32) *RuleUIDRange {
	return &RuleUIDRange{Start: start, End: end}
}

// RuleUIDRange represents rule uid range.
type RuleUIDRange struct {
	Start uint32
	End   uint32
}

func (r RuleUIDRange) Equal(x RuleUIDRange) bool {
	return r.Start == x.Start && r.End == x.End
}
