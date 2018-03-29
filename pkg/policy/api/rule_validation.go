// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	maxPorts = 40
	// MaxCIDRPrefixLengths is used to prevent compile failures at runtime.
	MaxCIDRPrefixLengths = 40
)

type exists struct{}

// Sanitize validates and sanitizes a policy rule. Minor edits such as
// capitalization of the protocol name are automatically fixed up. More
// fundamental violations will cause an error to be returned.
func (r Rule) Sanitize() error {

	if r.EndpointSelector.LabelSelector == nil {
		return fmt.Errorf("rule cannot have nil EndpointSelector")
	}

	for i := range r.Ingress {
		if err := r.Ingress[i].sanitize(); err != nil {
			return err
		}
	}

	for i := range r.Egress {
		if err := r.Egress[i].sanitize(); err != nil {
			return err
		}
	}

	return nil
}

func (i *IngressRule) sanitize() error {
	l3Members := map[string]int{
		"FromEndpoints": len(i.FromEndpoints),
		"FromCIDR":      len(i.FromCIDR),
		"FromCIDRSet":   len(i.FromCIDRSet),
		"FromEntities":  len(i.FromEntities),
	}
	l3DependentL4Support := map[interface{}]bool{
		"FromEndpoints": true,
		"FromCIDR":      false,
		"FromCIDRSet":   false,
		"FromEntities":  false,
	}
	for m1 := range l3Members {
		for m2 := range l3Members {
			if m2 != m1 && l3Members[m1] > 0 && l3Members[m2] > 0 {
				return fmt.Errorf("Combining %s and %s is not supported yet", m1, m2)
			}
		}
	}
	for member := range l3Members {
		if l3Members[member] > 0 && len(i.ToPorts) > 0 && !l3DependentL4Support[member] {
			return fmt.Errorf("Combining %s and ToPorts is not supported yet", member)
		}
	}

	for n := range i.ToPorts {
		if err := i.ToPorts[n].sanitize(); err != nil {
			return err
		}
	}

	prefixLengths := map[int]exists{}
	for n := range i.FromCIDR {
		prefixLength, err := i.FromCIDR[n].sanitize()
		if err != nil {
			return err
		}
		prefixLengths[prefixLength] = exists{}
	}

	for n := range i.FromCIDRSet {
		prefixLength, err := i.FromCIDRSet[n].sanitize()
		if err != nil {
			return err
		}
		prefixLengths[prefixLength] = exists{}
	}

	// FIXME GH-1781 count coalesced CIDRs and restrict the number of
	// prefix lengths based on the CIDRSet exclusions.
	if l := len(prefixLengths); l > MaxCIDRPrefixLengths {
		return fmt.Errorf("too many ingress CIDR prefix lengths %d/%d", l, MaxCIDRPrefixLengths)
	}

	return nil
}

func (e *EgressRule) sanitize() error {
	l3Members := map[string]int{
		"ToCIDR":      len(e.ToCIDR),
		"ToCIDRSet":   len(e.ToCIDRSet),
		"ToEndpoints": len(e.ToEndpoints),
		"ToEntities":  len(e.ToEntities),
		"ToServices":  len(e.ToServices),
	}
	l3DependentL4Support := map[interface{}]bool{
		"ToCIDR":      false,
		"ToCIDRSet":   false,
		"ToEndpoints": true,
		"ToEntities":  false,
		"ToServices":  false,
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

	for i := range e.ToPorts {
		if err := e.ToPorts[i].sanitize(); err != nil {
			return err
		}
	}

	prefixLengths := map[int]exists{}
	for i := range e.ToCIDR {
		prefixLength, err := e.ToCIDR[i].sanitize()
		if err != nil {
			return err
		}
		prefixLengths[prefixLength] = exists{}
	}
	for i := range e.ToCIDRSet {
		prefixLength, err := e.ToCIDRSet[i].sanitize()
		if err != nil {
			return err
		}
		prefixLengths[prefixLength] = exists{}
	}

	// FIXME GH-1781 count coalesced CIDRs and restrict the number of
	// prefix lengths based on the CIDRSet exclusions.
	if l := len(prefixLengths); l > MaxCIDRPrefixLengths {
		return fmt.Errorf("too many egress CIDR prefix lengths %d/%d", l, MaxCIDRPrefixLengths)
	}

	return nil
}

// Sanitize sanitizes Kafka rules
// TODO we need to add support to check
// wildcard and prefix/suffix later on.
func (kr *PortRuleKafka) Sanitize() error {
	if (len(kr.APIKey) > 0) && (len(kr.Role) > 0) {
		return fmt.Errorf("Cannot set both Role:%q and APIKey :%q together", kr.Role, kr.APIKey)
	}

	if len(kr.APIKey) > 0 {
		n, ok := KafkaAPIKeyMap[strings.ToLower(kr.APIKey)]
		if !ok {
			return fmt.Errorf("invalid Kafka APIKey :%q", kr.APIKey)
		}
		kr.apiKeyInt = append(kr.apiKeyInt, n)
	}

	if len(kr.Role) > 0 {
		err := kr.MapRoleToAPIKey()
		if err != nil {
			return fmt.Errorf("invalid Kafka APIRole :%q", kr.Role)
		}

	}

	if len(kr.APIVersion) > 0 {
		n, err := strconv.ParseInt(kr.APIVersion, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid Kafka APIVersion :%q",
				kr.APIVersion)
		}
		n16 := int16(n)
		kr.apiVersionInt = &n16
	}

	if len(kr.Topic) > 0 {
		if len(kr.Topic) > KafkaMaxTopicLen {
			return fmt.Errorf("kafka topic exceeds maximum len of %d",
				KafkaMaxTopicLen)
		}
		// This check allows suffix and prefix matching
		// for topic.
		if KafkaTopicValidChar.MatchString(kr.Topic) == false {
			return fmt.Errorf("invalid Kafka Topic name \"%s\"", kr.Topic)
		}
	}
	return nil
}

func (pr *L7Rules) sanitize() error {
	if (pr.HTTP != nil) && (pr.Kafka != nil) {
		return fmt.Errorf("multiple L7 protocol rule types specified in single rule")
	}

	if pr.Kafka != nil {
		for i := range pr.Kafka {
			if err := pr.Kafka[i].Sanitize(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (pr *PortRule) sanitize() error {
	if len(pr.Ports) > maxPorts {
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	for i := range pr.Ports {
		if err := pr.Ports[i].sanitize(); err != nil {
			return err
		}
	}

	// Sanitize L7 rules
	if pr.Rules != nil {
		if err := pr.Rules.sanitize(); err != nil {
			return err
		}
	}
	return nil
}

func (pp *PortProtocol) sanitize() error {
	if pp.Port == "" {
		return fmt.Errorf("Port must be specified")
	}

	p, err := strconv.ParseUint(pp.Port, 0, 16)
	if err != nil {
		return fmt.Errorf("Unable to parse port: %s", err)
	}

	if p == 0 {
		return fmt.Errorf("Port cannot be 0")
	}

	pp.Protocol, err = ParseL4Proto(string(pp.Protocol))
	if err != nil {
		return err
	}

	return nil
}

// sanitize the given CIDR. If successful, returns the prefixLength specified
// in the cidr and nil. Otherwise, returns (0, nil).
func (cidr CIDR) sanitize() (prefixLength int, err error) {
	strCIDR := string(cidr)
	if strCIDR == "" {
		return 0, fmt.Errorf("IP must be specified")
	}

	_, ipnet, err := net.ParseCIDR(strCIDR)
	if err == nil {
		// Returns the prefix length as zero if the mask is not continuous.
		prefixLength, _ = ipnet.Mask.Size()
		if prefixLength == 0 {
			return 0, fmt.Errorf("Mask length can not be zero")
		}
	} else {
		// Try to parse as a fully masked IP or an IP subnetwork
		ip := net.ParseIP(strCIDR)
		if ip == nil {
			return 0, fmt.Errorf("Unable to parse CIDR: %s", err)
		}
	}

	return prefixLength, nil
}

// sanitize validates a CIDRRule by checking that the CIDR prefix itself is
// valid, and ensuring that all of the exception CIDR prefixes are contained
// within the allowed CIDR prefix.
func (c *CIDRRule) sanitize() (prefixLength int, err error) {

	// Only allow notation <IP address>/<prefix>. Note that this differs from
	// the logic in api.CIDR.Sanitize().
	_, cidrNet, err := net.ParseCIDR(string(c.Cidr))
	if err != nil {
		return 0, err
	}

	// Returns the prefix length as zero if the mask is not continuous.
	prefixLength, _ = cidrNet.Mask.Size()
	if prefixLength == 0 {
		return 0, fmt.Errorf("Mask length can not be zero")
	}

	// Ensure that each provided exception CIDR prefix  is formatted correctly,
	// and is contained within the CIDR prefix to/from which we want to allow
	// traffic.
	for _, p := range c.ExceptCIDRs {
		exceptCIDRAddr, _, err := net.ParseCIDR(string(p))
		if err != nil {
			return 0, err
		}

		// Note: this also checks that the allow CIDR prefix and the exception
		// CIDR prefixes are part of the same address family.
		if !cidrNet.Contains(exceptCIDRAddr) {
			return 0, fmt.Errorf("allow CIDR prefix %s does not contain "+
				"exclude CIDR prefix %s", c.Cidr, p)
		}
	}

	return prefixLength, nil
}
