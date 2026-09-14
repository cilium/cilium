// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package qos

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Flow is the egress traffic a lookup is performed for. Ports are ignored for
// protocols that do not carry them.
type Flow struct {
	Dst     netip.Addr
	Proto   api.L4Proto
	SrcPort uint16
	DstPort uint16
}

// SelectsPod reports whether the policy applies to a pod with the given
// namespace and labels. An empty pod selector selects every pod in the
// namespace of the policy.
func SelectsPod(policy *v2alpha1.CiliumQoSPolicy, namespace string, podLabels map[string]string) (bool, error) {
	if policy.Namespace != namespace {
		return false, nil
	}
	selector, err := slimv1.LabelSelectorAsSelector(policy.Spec.PodSelector)
	if err != nil {
		return false, fmt.Errorf("policy %s/%s has an invalid pod selector: %w", policy.Namespace, policy.Name, err)
	}
	return selector.Matches(slimlabels.Set(podLabels)), nil
}

// Table holds the QoS rules that apply to one endpoint, in the order they were
// declared. Rules do not shadow each other: every rule is evaluated for every
// flow and the most specific match per mechanism wins.
type Table struct {
	rules []rule
}

type rule struct {
	// origin identifies the rule for tie-breaking, as "namespace/name#index".
	origin string

	toCIDR    []netip.Prefix
	toPorts   []portMatch
	fromPorts []portMatch

	classes []Class
}

// portMatch is one entry of a QoSPortRule, pre-parsed.
type portMatch struct {
	first, last uint16
	proto       api.L4Proto
}

// NewTable builds the rule table for a set of policies that have already been
// matched against an endpoint. classes holds every resolved CiliumQoSClass in
// the cluster, keyed by name.
//
// Malformed parts of a policy are dropped rather than failing the whole table,
// so that a typo in one class reference does not silently disable QoS for
// unrelated traffic. The dropped parts are returned so the caller can surface
// them on the policy status.
func NewTable(policies []*v2alpha1.CiliumQoSPolicy, classes map[string]Class) (*Table, []error) {
	var (
		table Table
		errs  []error
	)

	for _, policy := range policies {
		for i, egress := range policy.Spec.Egress {
			origin := fmt.Sprintf("%s/%s#%d", policy.Namespace, policy.Name, i)

			r := rule{origin: origin}

			for _, prefix := range egress.ToCIDR {
				if !prefix.IsValid() {
					errs = append(errs, fmt.Errorf("rule %s: invalid CIDR %q", origin, prefix))
					continue
				}
				r.toCIDR = append(r.toCIDR, prefix.Masked())
			}

			var err error
			if r.toPorts, err = parsePortRules(egress.ToPorts); err != nil {
				errs = append(errs, fmt.Errorf("rule %s: toPorts: %w", origin, err))
				continue
			}
			if r.fromPorts, err = parsePortRules(egress.FromPorts); err != nil {
				errs = append(errs, fmt.Errorf("rule %s: fromPorts: %w", origin, err))
				continue
			}

			for _, ref := range egress.QoSClassRefs {
				class, ok := classes[ref.Name]
				if !ok {
					errs = append(errs, fmt.Errorf("rule %s: references unknown or unresolved class %q", origin, ref.Name))
					continue
				}
				r.classes = append(r.classes, class)
			}

			if len(r.classes) == 0 {
				continue
			}

			table.rules = append(table.rules, r)
		}
	}

	return &table, errs
}

func parsePortRules(portRules []v2alpha1.QoSPortRule) ([]portMatch, error) {
	var out []portMatch

	for _, portRule := range portRules {
		for _, port := range portRule.Ports {
			first, err := strconv.ParseUint(port.Port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", port.Port, err)
			}

			match := portMatch{
				first: uint16(first),
				last:  uint16(first),
				proto: port.Protocol,
			}
			if port.EndPort != 0 {
				if port.EndPort < int32(first) || port.EndPort > 65535 {
					return nil, fmt.Errorf("endPort %d is not in [%d, 65535]", port.EndPort, first)
				}
				match.last = uint16(port.EndPort)
			}

			out = append(out, match)
		}
	}

	return out, nil
}

// Lookup returns the marking that applies to a flow: for every mechanism, the
// class selected by the most specific matching rule.
func (t *Table) Lookup(flow Flow) Marking {
	best := make(map[v2alpha1.QoSMechanismType]candidate, 2)

	for _, r := range t.rules {
		spec, ok := r.match(flow)
		if !ok {
			continue
		}

		for _, class := range r.classes {
			cand := candidate{spec: spec, class: class, origin: r.origin}
			if cur, ok := best[class.Mechanism]; !ok || cand.compare(cur) > 0 {
				best[class.Mechanism] = cand
			}
		}
	}

	var marking Marking
	if cand, ok := best[v2alpha1.QoSMechanismDSCP]; ok {
		dscp := cand.class.DSCP
		marking.DSCP = &dscp
	}
	if cand, ok := best[v2alpha1.QoSMechanismNodePriority]; ok {
		prio := cand.class.NodePriority
		marking.NodePriority = &prio
	}

	return marking
}

// specificity ranks how narrowly a rule matched a flow. Per the QoS API, an L4
// match is narrower than any L3 match, and a longer destination prefix is
// narrower than a shorter one.
type specificity struct {
	// l4 combines the destination and source port matches, the destination
	// dominating. An exact port beats a range, and an explicit protocol beats
	// a wildcard one.
	l4 int
	// cidr is the length of the matched destination prefix, or -1 when the
	// rule does not constrain the destination at all.
	cidr int
}

func (s specificity) compare(other specificity) int {
	if c := cmp.Compare(s.l4, other.l4); c != 0 {
		return c
	}
	return cmp.Compare(s.cidr, other.cidr)
}

type candidate struct {
	spec   specificity
	class  Class
	origin string
}

// compare orders two classes competing for the same mechanism: the more
// specific match wins, then the higher class priority, and finally the rule
// and class names, so that the outcome does not depend on iteration order.
func (c candidate) compare(other candidate) int {
	if r := c.spec.compare(other.spec); r != 0 {
		return r
	}
	if r := cmp.Compare(c.class.Priority, other.class.Priority); r != 0 {
		return r
	}
	if r := cmp.Compare(other.origin, c.origin); r != 0 {
		return r
	}
	return cmp.Compare(other.class.Name, c.class.Name)
}

func (r rule) match(flow Flow) (specificity, bool) {
	spec := specificity{cidr: -1}

	if len(r.toCIDR) > 0 {
		bits, ok := longestMatch(r.toCIDR, flow.Dst)
		if !ok {
			return specificity{}, false
		}
		spec.cidr = bits
	}

	dstScore, ok := matchPorts(r.toPorts, flow.Proto, flow.DstPort)
	if !ok {
		return specificity{}, false
	}
	srcScore, ok := matchPorts(r.fromPorts, flow.Proto, flow.SrcPort)
	if !ok {
		return specificity{}, false
	}
	spec.l4 = dstScore*8 + srcScore

	return spec, true
}

func longestMatch(prefixes []netip.Prefix, addr netip.Addr) (int, bool) {
	best := -1
	for _, prefix := range prefixes {
		if prefix.Contains(addr) && prefix.Bits() > best {
			best = prefix.Bits()
		}
	}
	return best, best >= 0
}

// matchPorts reports whether a flow satisfies a set of port matches, and how
// narrow the narrowest satisfied one is. An empty set matches everything and
// scores zero.
func matchPorts(matches []portMatch, proto api.L4Proto, port uint16) (int, bool) {
	if len(matches) == 0 {
		return 0, true
	}

	best := 0
	for _, match := range matches {
		if !protoMatches(match.proto, proto) {
			continue
		}
		if port < match.first || port > match.last {
			continue
		}

		score := 2
		if match.first == match.last {
			score = 4
		}
		if !isWildcardProto(match.proto) {
			score++
		}
		best = max(best, score)
	}

	return best, best > 0
}

func protoMatches(ruleProto, flowProto api.L4Proto) bool {
	if isWildcardProto(ruleProto) {
		return slices.Contains(portProtocols, flowProto)
	}
	return ruleProto == flowProto
}

func isWildcardProto(proto api.L4Proto) bool {
	return proto == "" || proto == api.ProtoAny
}

// portProtocols are the protocols a port match can apply to.
var portProtocols = []api.L4Proto{api.ProtoTCP, api.ProtoUDP, api.ProtoSCTP}
