// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/option"
)

const (
	maxPorts      = 40
	maxICMPFields = 40
)

// Sanitize validates and sanitizes a policy rule. Minor edits such as
// capitalization of the protocol name are automatically fixed up. More
// fundamental violations will cause an error to be returned.
func (r *Rule) Sanitize() error {
	// Fill in the default traffic posture of this Rule.
	// Default posture is per-direction (ingress or egress),
	// if there is a peer selector for that direction, the
	// default is deny, else allow.
	if r.EnableDefaultDeny.Egress == nil {
		x := len(r.Egress) > 0 || len(r.EgressDeny) > 0
		r.EnableDefaultDeny.Egress = &x
	}
	if r.EnableDefaultDeny.Ingress == nil {
		x := len(r.Ingress) > 0 || len(r.IngressDeny) > 0
		r.EnableDefaultDeny.Ingress = &x
	}

	if r.EndpointSelector.LabelSelector == nil && r.NodeSelector.LabelSelector == nil {
		return fmt.Errorf("rule must have one of EndpointSelector or NodeSelector")
	}
	if r.EndpointSelector.LabelSelector != nil && r.NodeSelector.LabelSelector != nil {
		return fmt.Errorf("rule cannot have both EndpointSelector and NodeSelector")
	}

	if r.EndpointSelector.LabelSelector != nil {
		if err := r.EndpointSelector.sanitize(); err != nil {
			return err
		}
	}

	var hostPolicy bool
	if r.NodeSelector.LabelSelector != nil {
		if err := r.NodeSelector.sanitize(); err != nil {
			return err
		}
		hostPolicy = true
	}

	for i := range r.Ingress {
		if err := r.Ingress[i].sanitize(); err != nil {
			return err
		}
		if hostPolicy {
			if len(countL7Rules(r.Ingress[i].ToPorts)) > 0 {
				return fmt.Errorf("host policies do not support L7 rules yet")
			}
		}
	}

	for i := range r.Egress {
		if err := r.Egress[i].sanitize(); err != nil {
			return err
		}
		if hostPolicy {
			if len(countL7Rules(r.Egress[i].ToPorts)) > 0 {
				return fmt.Errorf("host policies do not support L7 rules yet")
			}
		}
	}

	return nil
}

func countL7Rules(ports []PortRule) map[string]int {
	result := make(map[string]int)
	for _, port := range ports {
		if !port.Rules.IsEmpty() {
			result["DNS"] += len(port.Rules.DNS)
			result["HTTP"] += len(port.Rules.HTTP)
			result["Kafka"] += len(port.Rules.Kafka)
		}
	}
	return result
}

func (i *IngressRule) sanitize() error {
	l3Members := map[string]int{
		"FromEndpoints": len(i.FromEndpoints),
		"FromCIDR":      len(i.FromCIDR),
		"FromCIDRSet":   len(i.FromCIDRSet),
		"FromEntities":  len(i.FromEntities),
	}
	l7Members := countL7Rules(i.ToPorts)
	l7IngressSupport := map[string]bool{
		"DNS":   false,
		"Kafka": true,
		"HTTP":  true,
	}

	for m1 := range l3Members {
		for m2 := range l3Members {
			if m2 != m1 && l3Members[m1] > 0 && l3Members[m2] > 0 {
				return fmt.Errorf("Combining %s and %s is not supported yet", m1, m2)
			}
		}
	}

	if len(l7Members) > 0 && !option.Config.EnableL7Proxy {
		return errors.New("L7 policy is not supported since L7 proxy is not enabled")
	}
	for member := range l7Members {
		if l7Members[member] > 0 && !l7IngressSupport[member] {
			return fmt.Errorf("L7 protocol %s is not supported on ingress yet", member)
		}
	}

	if len(i.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(i.ICMPs) > 0 && len(i.ToPorts) > 0 {
		return fmt.Errorf("The ICMPs block may only be present without ToPorts. Define a separate rule to use ToPorts.")
	}

	for _, es := range i.FromEndpoints {
		if err := es.sanitize(); err != nil {
			return err
		}
	}

	for _, es := range i.FromRequires {
		if err := es.sanitize(); err != nil {
			return err
		}
	}

	for n := range i.ToPorts {
		if err := i.ToPorts[n].sanitize(true); err != nil {
			return err
		}
	}

	for n := range i.ICMPs {
		if err := i.ICMPs[n].verify(); err != nil {
			return err
		}
	}

	for n := range i.FromCIDR {
		if err := i.FromCIDR[n].sanitize(); err != nil {
			return err
		}
	}

	for n := range i.FromCIDRSet {
		if err := i.FromCIDRSet[n].sanitize(); err != nil {
			return err
		}
	}

	for _, fromEntity := range i.FromEntities {
		_, ok := EntitySelectorMapping[fromEntity]
		if !ok {
			return fmt.Errorf("unsupported entity: %s", fromEntity)
		}
	}

	i.SetAggregatedSelectors()

	return nil
}

func (e *EgressRule) sanitize() error {
	l3Members := map[string]int{
		"ToCIDR":      len(e.ToCIDR),
		"ToCIDRSet":   len(e.ToCIDRSet),
		"ToEndpoints": len(e.ToEndpoints),
		"ToEntities":  len(e.ToEntities),
		"ToServices":  len(e.ToServices),
		"ToFQDNs":     len(e.ToFQDNs),
		"ToGroups":    len(e.ToGroups),
	}
	l3DependentL4Support := map[interface{}]bool{
		"ToCIDR":      true,
		"ToCIDRSet":   true,
		"ToEndpoints": true,
		"ToEntities":  true,
		"ToServices":  false, // see https://github.com/cilium/cilium/issues/20067
		"ToFQDNs":     true,
		"ToGroups":    true,
	}
	l7Members := countL7Rules(e.ToPorts)
	l7EgressSupport := map[string]bool{
		"DNS":   true,
		"Kafka": true,
		"HTTP":  true,
	}

	for m1 := range l3Members {
		for m2 := range l3Members {
			if m2 != m1 && l3Members[m1] > 0 && l3Members[m2] > 0 {
				return fmt.Errorf("Combining %s and %s is not supported yet", m1, m2)
			}
		}
	}
	for member := range l3Members {
		if l3Members[member] > 0 && len(e.ToPorts) > 0 && !l3DependentL4Support[member] {
			return fmt.Errorf("Combining %s and ToPorts is not supported yet", member)
		}
	}

	if len(l7Members) > 0 && !option.Config.EnableL7Proxy {
		return errors.New("L7 policy is not supported since L7 proxy is not enabled")
	}
	for member := range l7Members {
		if l7Members[member] > 0 && !l7EgressSupport[member] {
			return fmt.Errorf("L7 protocol %s is not supported on egress yet", member)
		}
	}

	if len(e.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(e.ICMPs) > 0 && len(e.ToPorts) > 0 {
		return fmt.Errorf("The ICMPs block may only be present without ToPorts. Define a separate rule to use ToPorts.")
	}

	for _, es := range e.ToEndpoints {
		if err := es.sanitize(); err != nil {
			return err
		}
	}

	for _, es := range e.ToRequires {
		if err := es.sanitize(); err != nil {
			return err
		}
	}

	for i := range e.ToPorts {
		if err := e.ToPorts[i].sanitize(false); err != nil {
			return err
		}
	}

	for n := range e.ICMPs {
		if err := e.ICMPs[n].verify(); err != nil {
			return err
		}
	}

	for i := range e.ToCIDR {
		if err := e.ToCIDR[i].sanitize(); err != nil {
			return err
		}
	}
	for i := range e.ToCIDRSet {
		if err := e.ToCIDRSet[i].sanitize(); err != nil {
			return err
		}
	}

	for _, toEntity := range e.ToEntities {
		_, ok := EntitySelectorMapping[toEntity]
		if !ok {
			return fmt.Errorf("unsupported entity: %s", toEntity)
		}
	}

	for i := range e.ToFQDNs {
		err := e.ToFQDNs[i].sanitize()
		if err != nil {
			return err
		}
	}

	e.SetAggregatedSelectors()

	return nil
}

func (pr *L7Rules) sanitize(ports []PortProtocol) error {
	nTypes := 0

	if pr.HTTP != nil {
		nTypes++
		for i := range pr.HTTP {
			if err := pr.HTTP[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if pr.Kafka != nil {
		nTypes++
		for i := range pr.Kafka {
			if err := pr.Kafka[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if pr.DNS != nil {
		// Forthcoming TPROXY redirection restricts DNS proxy to the standard DNS port (53).
		// Require the port 53 be explicitly configured, and disallow other port numbers.
		if len(ports) == 0 {
			return fmt.Errorf("Port 53 must be specified for DNS rules")
		}

		nTypes++
		for i := range pr.DNS {
			if err := pr.DNS[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if pr.L7 != nil && pr.L7Proto == "" {
		return fmt.Errorf("'l7' may only be specified when a 'l7proto' is also specified")
	}
	if pr.L7Proto != "" {
		nTypes++
		for i := range pr.L7 {
			if err := pr.L7[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if nTypes > 1 {
		return fmt.Errorf("multiple L7 protocol rule types specified in single rule")
	}
	return nil
}

func (pr *PortRule) sanitize(ingress bool) error {
	hasDNSRules := pr.Rules != nil && len(pr.Rules.DNS) > 0
	if ingress && hasDNSRules {
		return fmt.Errorf("DNS rules are not allowed on ingress")
	}

	if len(pr.ServerNames) > 0 && !pr.Rules.IsEmpty() && pr.TerminatingTLS == nil {
		return fmt.Errorf("ServerNames are not allowed with L7 rules without TLS termination")
	}
	for _, sn := range pr.ServerNames {
		if sn == "" {
			return fmt.Errorf("Empty server name is not allowed")
		}
	}

	if len(pr.Ports) > maxPorts {
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	haveZeroPort := false
	for i := range pr.Ports {
		var isZero bool
		var err error
		if isZero, err = pr.Ports[i].sanitize(); err != nil {
			return err
		}
		if isZero {
			haveZeroPort = true
		}
		// DNS L7 rules can be TCP, UDP or ANY, all others are TCP only.
		switch {
		case pr.Rules.IsEmpty(), hasDNSRules:
			// nothing to do if no rules OR they are DNS rules (note the comma above)
		case pr.Ports[i].Protocol != ProtoTCP:
			return fmt.Errorf("L7 rules can only apply to TCP (not %s) except for DNS rules", pr.Ports[i].Protocol)
		}
	}

	listener := pr.Listener
	if listener != nil {
		// For now we have only tested custom listener support on the egress path.  TODO
		// (jrajahalme): Lift this limitation in follow-up work once proper testing has been
		// done on the ingress path.
		if ingress {
			return fmt.Errorf("Listener is not allowed on ingress (%s)", listener.Name)
		}
		// There is no quarantee that Listener will support Cilium policy enforcement.  Even
		// now proxylib-based enforcement (e.g, Kafka) may work, but has not been tested.
		// TODO (jrajahalme): Lift this limitation in follow-up work for proxylib based
		// parsers if needed and when tested.
		if !pr.Rules.IsEmpty() {
			return fmt.Errorf("Listener is not allowed with L7 rules (%s)", listener.Name)
		}
	}

	// Sanitize L7 rules
	if !pr.Rules.IsEmpty() {
		if haveZeroPort {
			return fmt.Errorf("L7 rules can not be used when a port is 0")
		}

		if err := pr.Rules.sanitize(pr.Ports); err != nil {
			return err
		}
	}
	return nil
}

func (pp *PortProtocol) sanitize() (isZero bool, err error) {
	if pp.Port == "" {
		return isZero, fmt.Errorf("Port must be specified")
	}

	// Port names are formatted as IANA Service Names.  This means that
	// some legal numeric literals are no longer considered numbers, e.g,
	// 0x10 is now considered a name rather than number 16.
	if iana.IsSvcName(pp.Port) {
		pp.Port = strings.ToLower(pp.Port) // Normalize for case insensitive comparison
	} else {
		p, err := strconv.ParseUint(pp.Port, 0, 16)
		if err != nil {
			return isZero, fmt.Errorf("Unable to parse port: %w", err)
		}
		isZero = p == 0
	}

	pp.Protocol, err = ParseL4Proto(string(pp.Protocol))
	return isZero, err
}

func (ir *ICMPRule) verify() error {
	if len(ir.Fields) > maxICMPFields {
		return fmt.Errorf("too many types, the max is %d", maxICMPFields)
	}

	for _, f := range ir.Fields {
		if f.Family != IPv4Family && f.Family != IPv6Family && f.Family != "" {
			return fmt.Errorf("wrong family: %s", f.Family)
		}
	}

	return nil
}

// sanitize the given CIDR.
func (c CIDR) sanitize() error {
	strCIDR := string(c)
	if strCIDR == "" {
		return fmt.Errorf("IP must be specified")
	}

	prefix, err := netip.ParsePrefix(strCIDR)
	if err != nil {
		_, err := netip.ParseAddr(strCIDR)
		if err != nil {
			return fmt.Errorf("unable to parse CIDR: %w", err)
		}
		return nil
	}
	prefixLength := prefix.Bits()
	if prefixLength < 0 {
		return fmt.Errorf("CIDR cannot specify non-contiguous mask %s", prefix)
	}

	return nil
}

// sanitize validates a CIDRRule by checking that the CIDR prefix itself is
// valid, and ensuring that all of the exception CIDR prefixes are contained
// within the allowed CIDR prefix.
func (c *CIDRRule) sanitize() error {
	// Only allow notation <IP address>/<prefix>. Note that this differs from
	// the logic in api.CIDR.Sanitize().
	prefix, err := netip.ParsePrefix(string(c.Cidr))
	if err != nil {
		return fmt.Errorf("Unable to parse CIDRRule %q: %w", c.Cidr, err)
	}

	prefixLength := prefix.Bits()
	if prefixLength < 0 {
		return fmt.Errorf("CIDR cannot specify non-contiguous mask %s", prefix)
	}

	// Ensure that each provided exception CIDR prefix  is formatted correctly,
	// and is contained within the CIDR prefix to/from which we want to allow
	// traffic.
	for _, p := range c.ExceptCIDRs {
		except, err := netip.ParsePrefix(string(p))
		if err != nil {
			return err
		}

		// Note: this also checks that the allow CIDR prefix and the exception
		// CIDR prefixes are part of the same address family.
		if !prefix.Contains(except.Addr()) {
			return fmt.Errorf("allow CIDR prefix %s does not contain "+
				"exclude CIDR prefix %s", c.Cidr, p)
		}
	}

	return nil
}
