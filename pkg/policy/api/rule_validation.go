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
	// MaxCIDREntries is used to prevent compile failures at runtime.
	MaxCIDREntries = 40
)

// Sanitize validates and sanitizes a policy rule. Minor edits such as
// capitalization of the protocol name are automatically fixed up. More
// fundamental violations will cause an error to be returned.
func (r Rule) Sanitize() error {
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
	if len(i.FromCIDR) > 0 && len(i.FromEndpoints) > 0 {
		return fmt.Errorf("Combining FromCIDR and FromEndpoints is not supported yet")
	}

	if len(i.FromCIDR) > 0 && len(i.ToPorts) > 0 {
		return fmt.Errorf("Combining ToPorts and FromCIDR is not supported yet")
	}

	for n := range i.ToPorts {
		if err := i.ToPorts[n].sanitize(); err != nil {
			return err
		}
	}

	if l := len(i.FromCIDR); l > MaxCIDREntries {
		return fmt.Errorf("too many ingress CIDR entries %d/%d", l, MaxCIDREntries)
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

	return nil
}

func (e *EgressRule) sanitize() error {

	// TODO: GH-XXXX (support combining of label-based L3 and CIDR-based L3)
	if len(e.ToCIDR) > 0 && len(e.ToEndpoints) > 0 {
		return fmt.Errorf("Combining ToCIDR and ToEndpoints is not supported yet")
	}

	// TODO: GH-XXXX (support combining of CIDR-based L3 and L4)
	if len(e.ToCIDR) > 0 && len(e.ToPorts) > 0 {
		return fmt.Errorf("Combining ToPorts and ToCIDR is not supported yet")
	}

	// TODO: GH-XXXX (support egress combining of label-based L3 and L4)
	if len(e.ToEndpoints) > 0 && len(e.ToPorts) > 0 {
		return fmt.Errorf("Combining ToPorts and ToEndpoints is not supported yet")
	}

	for i := range e.ToPorts {
		if err := e.ToPorts[i].sanitize(); err != nil {
			return err
		}
	}
	if l := len(e.ToCIDR); l > MaxCIDREntries {
		return fmt.Errorf("too many egress CIDR entries %d/%d", l, MaxCIDREntries)
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

	return nil
}

// Sanitize sanitizes Kafka rules
// TODO we need to add support to check
// wildcard and prefix/suffix later on.
func (kr *PortRuleKafka) Sanitize() error {
	if len(kr.APIKey) > 0 {
		n, ok := KafkaAPIKeyMap[strings.ToLower(kr.APIKey)]
		if !ok {
			return fmt.Errorf("invalid Kafka APIKey :%q", kr.APIKey)
		}
		kr.apiKeyInt = &n
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

func (cidr CIDR) sanitize() error {
	strCIDR := string(cidr)
	if strCIDR == "" {
		return fmt.Errorf("IP must be specified")
	}

	_, ipnet, err := net.ParseCIDR(strCIDR)
	if err == nil {
		// Returns the prefix length as zero if the mask is not continuous.
		ones, _ := ipnet.Mask.Size()
		if ones == 0 {
			return fmt.Errorf("Mask length can not be zero")
		}
	} else {
		// Try to parse as a fully masked IP or an IP subnetwork
		ip := net.ParseIP(strCIDR)
		if ip == nil {
			return fmt.Errorf("Unable to parse CIDR: %s", err)
		}
	}

	return nil
}

// sanitize validates a CIDRRule by checking that the CIDR prefix itself is
// valid, and ensuring that all of the exception CIDR prefixes are contained
// within the allowed CIDR prefix.
func (c *CIDRRule) sanitize() error {

	// Only allow notation <IP address>/<prefix>. Note that this differs from
	// the logic in api.CIDR.Sanitize().
	_, cidrNet, err := net.ParseCIDR(string(c.Cidr))

	if err != nil {
		return err
	}

	// Returns the prefix length as zero if the mask is not continuous.
	ones, _ := cidrNet.Mask.Size()
	if ones == 0 {
		return fmt.Errorf("Mask length can not be zero")
	}

	// Ensure that each provided exception CIDR prefix  is formatted correctly,
	// and is contained within the CIDR prefix to/from which we want to allow
	// traffic.
	for _, p := range c.ExceptCIDRs {
		exceptCIDRAddr, _, err := net.ParseCIDR(string(p))
		if err != nil {
			return err
		}

		// Note: this also checks that the allow CIDR prefix and the exception
		// CIDR prefixes are part of the same address family.
		if !cidrNet.Contains(exceptCIDRAddr) {
			return fmt.Errorf("allow CIDR prefix %s does not contain "+
				"exclude CIDR prefix %s", c.Cidr, p)
		}
	}

	return nil
}
