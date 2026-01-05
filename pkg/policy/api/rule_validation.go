// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/option"
)

func (r *Rule) Validate() error {
	if len(r.Ingress) == 0 && len(r.IngressDeny) == 0 && len(r.Egress) == 0 && len(r.EgressDeny) == 0 {
		return fmt.Errorf("rule must have at least one of Ingress, IngressDeny, Egress, EgressDeny")
	}

	if r.EndpointSelector.LabelSelector == nil && r.NodeSelector.LabelSelector == nil {
		return errors.New("rule must have one of EndpointSelector or NodeSelector")
	}
	if r.EndpointSelector.LabelSelector != nil && r.NodeSelector.LabelSelector != nil {
		return errors.New("rule cannot have both EndpointSelector and NodeSelector")
	}

	if r.EndpointSelector.LabelSelector != nil {
		if err := r.EndpointSelector.Validate(); err != nil {
			return err
		}
	}

	var hostPolicy bool
	if r.NodeSelector.LabelSelector != nil {
		if err := r.NodeSelector.Validate(); err != nil {
			return err
		}
		hostPolicy = true
	}

	for i := range r.Ingress {
		if err := r.Ingress[i].Validate(hostPolicy); err != nil {
			return err
		}
	}

	for i := range r.IngressDeny {
		if err := r.IngressDeny[i].Validate(); err != nil {
			return err
		}
	}

	for i := range r.Egress {
		if err := r.Egress[i].Validate(hostPolicy); err != nil {
			return err
		}
	}

	for i := range r.EgressDeny {
		if err := r.EgressDeny[i].Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (i *IngressRule) Validate(hostPolicy bool) error {
	l7Members := countL7Rules(i.ToPorts)
	l7IngressSupport := map[string]bool{
		"DNS":   false,
		"Kafka": true,
		"HTTP":  true,
	}

	if err := i.IngressCommonRule.Validate(); err != nil {
		return err
	}

	if hostPolicy && len(l7Members) > 0 {
		return errors.New("L7 policy is not supported on host ingress yet")
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
		return errUnsupportedICMPWithToPorts
	}

	for n := range i.ToPorts {
		if err := i.ToPorts[n].Validate(true); err != nil {
			return err
		}
	}

	for n := range i.ICMPs {
		if err := i.ICMPs[n].Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (i *IngressRule) Sanitize() {
	for idx := range i.ToPorts {
		i.ToPorts[idx].Sanitize()
	}
}

func (i *IngressDenyRule) Validate() error {
	if err := i.IngressCommonRule.Validate(); err != nil {
		return err
	}

	if len(i.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(i.ICMPs) > 0 && len(i.ToPorts) > 0 {
		return errUnsupportedICMPWithToPorts
	}

	for n := range i.ToPorts {
		if err := i.ToPorts[n].Validate(); err != nil {
			return err
		}
	}

	for n := range i.ICMPs {
		if err := i.ICMPs[n].Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (i *IngressDenyRule) Sanitize() {
	for idx := range i.ToPorts {
		i.ToPorts[idx].Sanitize()
	}
}

func (i *IngressCommonRule) Validate() error {
	l3Members := map[string]int{
		"FromEndpoints": len(i.FromEndpoints),
		"FromCIDR":      len(i.FromCIDR),
		"FromCIDRSet":   len(i.FromCIDRSet),
		"FromEntities":  len(i.FromEntities),
		"FromNodes":     len(i.FromNodes),
		"FromGroups":    len(i.FromGroups),
	}

	for m1 := range l3Members {
		for m2 := range l3Members {
			if m2 != m1 && l3Members[m1] > 0 && l3Members[m2] > 0 {
				return fmt.Errorf("combining %s and %s is not supported yet", m1, m2)
			}
		}
	}

	var retErr error

	if len(i.FromNodes) > 0 && !option.Config.EnableNodeSelectorLabels {
		retErr = ErrFromToNodesRequiresNodeSelectorOption
	}

	for n := range i.FromEndpoints {
		if err := i.FromEndpoints[n].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for n := range i.FromNodes {
		if err := i.FromNodes[n].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for n := range i.FromCIDR {
		if err := i.FromCIDR[n].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for n := range i.FromCIDRSet {
		if err := i.FromCIDRSet[n].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for _, fromEntity := range i.FromEntities {
		_, ok := EntitySelectorMapping[fromEntity]
		if !ok {
			return errors.Join(fmt.Errorf("unsupported entity: %s", fromEntity), retErr)
		}
	}

	return retErr
}

func (e *EgressRule) Validate(hostPolicy bool) error {
	l3Members := e.l3Members()
	l3DependentL4Support := e.l3DependentL4Support()
	l7Members := countL7Rules(e.ToPorts)
	l7EgressSupport := map[string]bool{
		"DNS":   true,
		"Kafka": !hostPolicy,
		"HTTP":  !hostPolicy,
	}

	if err := e.EgressCommonRule.Validate(l3Members); err != nil {
		return err
	}

	for member := range l3Members {
		if l3Members[member] > 0 && len(e.ToPorts) > 0 && !l3DependentL4Support[member] {
			return fmt.Errorf("combining %s and ToPorts is not supported yet", member)
		}
	}

	if len(l7Members) > 0 && !option.Config.EnableL7Proxy {
		return errors.New("L7 policy is not supported since L7 proxy is not enabled")
	}
	for member := range l7Members {
		if l7Members[member] > 0 && !l7EgressSupport[member] {
			where := ""
			if hostPolicy {
				where = "host "
			}
			return fmt.Errorf("L7 protocol %s is not supported on %segress yet", member, where)
		}
	}

	if len(e.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(e.ICMPs) > 0 && len(e.ToPorts) > 0 {
		return errUnsupportedICMPWithToPorts
	}

	for i := range e.ToPorts {
		if err := e.ToPorts[i].Validate(false); err != nil {
			return err
		}
	}

	for n := range e.ICMPs {
		if err := e.ICMPs[n].Validate(); err != nil {
			return err
		}
	}

	for i := range e.ToFQDNs {
		err := e.ToFQDNs[i].Validate()
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *EgressRule) Sanitize() {
	for i := range e.ToPorts {
		e.ToPorts[i].Sanitize()
	}
}

func (e *EgressDenyRule) Validate() error {
	l3Members := e.l3Members()
	l3DependentL4Support := e.l3DependentL4Support()

	if err := e.EgressCommonRule.Validate(l3Members); err != nil {
		return err
	}

	for member := range l3Members {
		if l3Members[member] > 0 && len(e.ToPorts) > 0 && !l3DependentL4Support[member] {
			return fmt.Errorf("combining %s and ToPorts is not supported yet", member)
		}
	}

	if len(e.ICMPs) > 0 && !option.Config.EnableICMPRules {
		return fmt.Errorf("ICMP rules can only be applied when the %q flag is set", option.EnableICMPRules)
	}

	if len(e.ICMPs) > 0 && len(e.ToPorts) > 0 {
		return errUnsupportedICMPWithToPorts
	}

	for i := range e.ToPorts {
		if err := e.ToPorts[i].Validate(); err != nil {
			return err
		}
	}

	for n := range e.ICMPs {
		if err := e.ICMPs[n].Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (e *EgressDenyRule) Sanitize() {
	for i := range e.ToPorts {
		e.ToPorts[i].Sanitize()
	}
}

func (e *EgressCommonRule) Validate(l3Members map[string]int) error {
	for m1 := range l3Members {
		for m2 := range l3Members {
			if m2 != m1 && l3Members[m1] > 0 && l3Members[m2] > 0 {
				return fmt.Errorf("combining %s and %s is not supported yet", m1, m2)
			}
		}
	}

	var retErr error

	if len(e.ToNodes) > 0 && !option.Config.EnableNodeSelectorLabels {
		retErr = ErrFromToNodesRequiresNodeSelectorOption
	}

	for i := range e.ToEndpoints {
		if err := e.ToEndpoints[i].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for i := range e.ToNodes {
		if err := e.ToNodes[i].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for i := range e.ToCIDR {
		if err := e.ToCIDR[i].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}
	for i := range e.ToCIDRSet {
		if err := e.ToCIDRSet[i].Validate(); err != nil {
			return errors.Join(err, retErr)
		}
	}

	for _, toEntity := range e.ToEntities {
		_, ok := EntitySelectorMapping[toEntity]
		if !ok {
			return errors.Join(fmt.Errorf("unsupported entity: %s", toEntity), retErr)
		}
	}

	return retErr
}

func (pr *L7Rules) Validate(ports []PortProtocol) error {
	nTypes := 0

	if pr.HTTP != nil {
		nTypes++
		for i := range pr.HTTP {
			if err := pr.HTTP[i].Validate(); err != nil {
				return err
			}
		}
	}

	if pr.Kafka != nil {
		nTypes++
		for i := range pr.Kafka {
			// Kafka rule validation comes from cilium/proxy. Use existing sanitize
			// method which doesn't mutate the object.
			if err := pr.Kafka[i].Sanitize(); err != nil {
				return err
			}
		}
	}

	if pr.DNS != nil {
		// Forthcoming TPROXY redirection restricts DNS proxy to the standard DNS port (53).
		// Require the port 53 be explicitly configured, and disallow other port numbers.
		if len(ports) == 0 {
			return errors.New("port 53 must be specified for DNS rules")
		}

		nTypes++
		for i := range pr.DNS {
			if err := pr.DNS[i].Validate(); err != nil {
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
			if err := pr.L7[i].Validate(); err != nil {
				return err
			}
		}
	}

	if nTypes > 1 {
		return fmt.Errorf("multiple L7 protocol rule types specified in single rule")
	}
	return nil
}

func (pr *PortRule) Validate(ingress bool) error {
	hasDNSRules := pr.Rules != nil && len(pr.Rules.DNS) > 0
	if ingress && hasDNSRules {
		return fmt.Errorf("DNS rules are not allowed on ingress")
	}

	if len(pr.ServerNames) > 0 && !pr.Rules.IsEmpty() && pr.TerminatingTLS == nil {
		return fmt.Errorf("ServerNames are not allowed with L7 rules without TLS termination")
	}
	if slices.Contains(pr.ServerNames, "") {
		return errEmptyServerName
	}

	if len(pr.Ports) > maxPorts {
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	haveZeroPort := false
	for i := range pr.Ports {
		var isZero bool
		var err error
		if isZero, err = pr.Ports[i].Validate(hasDNSRules); err != nil {
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
		if ingress && !TestAllowIngressListener {
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
			return errors.New("L7 rules can not be used when a port is 0")
		}

		if err := pr.Rules.Validate(pr.Ports); err != nil {
			return err
		}
	}
	return nil
}

func (pr *PortRule) Sanitize() {
	for i := range pr.Ports {
		pr.Ports[i].Sanitize()
	}
}

func (pr *PortDenyRule) Validate() error {
	if len(pr.Ports) > maxPorts {
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	for i := range pr.Ports {
		if _, err := pr.Ports[i].Validate(false); err != nil {
			return err
		}
	}

	return nil
}

func (pr *PortDenyRule) Sanitize() {
	for i := range pr.Ports {
		pr.Ports[i].Sanitize()
	}
}

func (pp *PortProtocol) Validate(hasDNSRules bool) (isZero bool, err error) {
	if pp.Port == "" {
		if !option.Config.EnableExtendedIPProtocols {
			return isZero, errors.New("port must be specified")
		}
	}

	// Port names are formatted as IANA Service Names.  This means that
	// some legal numeric literals are no longer considered numbers, e.g,
	// 0x10 is now considered a name rather than number 16.
	if iana.IsSvcName(pp.Port) {
		pp.Port = strings.ToLower(pp.Port) // Normalize for case insensitive comparison
	} else if pp.Port != "" {
		if pp.Port != "0" && (pp.Protocol == ProtoVRRP || pp.Protocol == ProtoIGMP) {
			return isZero, errors.New("port must be empty or 0")
		}
		p, err := strconv.ParseUint(pp.Port, 0, 16)
		if err != nil {
			return isZero, fmt.Errorf("unable to parse port: %w", err)
		}
		isZero = p == 0
		if hasDNSRules && pp.EndPort > int32(p) {
			return isZero, errors.New("DNS rules do not support port ranges")
		}
	}

	_, err = ParseL4Proto(string(pp.Protocol))
	return isZero, err
}

func (pp *PortProtocol) Sanitize() {
	// Assumes the object has been validated beforehand.
	if l4Proto, err := ParseL4Proto(string(pp.Protocol)); err == nil {
		pp.Protocol = l4Proto
	}
}

func (ir *ICMPRule) Validate() error {
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
func (c CIDR) Validate() error {
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
func (c *CIDRRule) Validate() error {
	// Exactly one of CIDR, CIDRGroupRef, or CIDRGroupSelector must be set
	cnt := 0
	if len(c.CIDRGroupRef) > 0 {
		cnt++
	}
	if len(c.Cidr) > 0 {
		cnt++
	}
	if c.CIDRGroupSelector.LabelSelector != nil {
		cnt++
		// CIDRGroupSelector select CIDRGroup by labels and cannot have source prefix.
		// Validate them as regular K8s label selector.
		if err := c.CIDRGroupSelector.ValidateAsK8sLabelSelector(); err != nil {
			return fmt.Errorf("failed to sanitize cidrGroupSelector %v: %w", c.CIDRGroupSelector.String(), err)
		}
	}
	if cnt == 0 {
		return fmt.Errorf("one of cidr, cidrGroupRef, or cidrGroupSelector is required")
	}
	if cnt > 1 {
		return fmt.Errorf("more than one of cidr, cidrGroupRef, or cidrGroupSelector may not be set")
	}

	if len(c.CIDRGroupRef) > 0 || c.CIDRGroupSelector.LabelSelector != nil {
		return nil // these are selectors;
	}

	// Only allow notation <IP address>/<prefix>. Note that this differs from
	// the logic in api.CIDR.Sanitize().
	prefix, err := netip.ParsePrefix(string(c.Cidr))
	if err != nil {
		return fmt.Errorf("unable to parse CIDRRule %q: %w", c.Cidr, err)
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
