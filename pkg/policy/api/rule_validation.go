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

// Validate validates a policy rule
func (r Rule) Validate() error {
	for _, i := range r.Ingress {
		if err := i.Validate(); err != nil {
			return err
		}
	}

	for _, e := range r.Egress {
		if err := e.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates an ingress policy rule
func (i IngressRule) Validate() error {
	for _, p := range i.ToPorts {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	if l := len(i.FromCIDR); l > MaxCIDREntries {
		return fmt.Errorf("too many ingress L3 entries %d/%d", l, MaxCIDREntries)
	}
	for _, p := range i.FromCIDR {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates an egress policy rule
func (e EgressRule) Validate() error {
	for _, p := range e.ToPorts {
		if err := p.Validate(); err != nil {
			return err
		}
	}
	if l := len(e.ToCIDR); l > MaxCIDREntries {
		return fmt.Errorf("too many egress L3 entries %d/%d", l, MaxCIDREntries)
	}
	for _, p := range e.ToCIDR {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates Kafka rules
// TODO we need to add support to check
// wildcard and prefix/suffix later on.
func (kr PortRuleKafka) Validate() error {
	if len(kr.APIKey) > 0 {
		switch kr.APIKey {
		case KafkaProduceReq:
		case KafkaFetchReq:
		case KafkaCreateTopicsReq:
		case KafkaDeleteTopicsReq:
		default:
			return fmt.Errorf("Invalid Kafka APIKey :", kr.APIKey)
		}
	}

	if len(kr.APIVersion) > 0 {
		switch kr.APIVersion {
		case "0":
		case "1":
		case "2":
		case "3":
		default:
			return fmt.Errorf("Invalid Kafka APIVersion :", kr.APIVersion)
		}
	}

	if len(kr.Topic) > 0 {
		if len(kr.Topic) > KafkaMaxTopicLen {
			return fmt.Errorf("Kafka Topic exceeds maximum len of ",
				KafkaMaxTopicLen)
		}
		// This check allows suffix and prefix matching
		// for topic.
		if KafkaTopicValidChar.MatchString(kr.Topic) == false {
			return fmt.Errorf("Invalid Kafka Topic name")
		}
	}
	return nil
}

// Validate validates L7 rules
func (pr *L7Rules) Validate() error {
	if (pr.HTTP != nil) && (pr.Kafka != nil) {
		return fmt.Errorf("multiple rules for the same port")
	}

	if pr.Kafka != nil {
		for _, kafkaRules := range pr.Kafka {
			if err := kafkaRules.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Validate validates a port policy rule
func (pr PortRule) Validate() error {
	if len(pr.Ports) > maxPorts {
		return fmt.Errorf("too many ports, the max is %d", maxPorts)
	}
	for _, p := range pr.Ports {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	// Validate L7 rules
	if pr.Rules != nil {
		if err := pr.Rules.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate validates a port/protocol pair
func (pp PortProtocol) Validate() error {
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

	switch strings.ToLower(pp.Protocol) {
	case "", "any", "tcp", "udp":
	default:
		return fmt.Errorf("Invalid protocol %q, must be { tcp | udp }", pp.Protocol)
	}

	return nil
}

// Validate CIDR
func (cidr CIDR) Validate() error {
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
