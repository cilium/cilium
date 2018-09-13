// Copyright 2018 Authors of Cilium
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

package proxylib

import (
	"fmt"
	"reflect"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

type PolicyUpdater interface {
	Update(resp *envoy_api_v2.DiscoveryResponse) error
}

// Each L7 rule implements this interface
type L7NetworkPolicyRule interface {
	Matches(interface{}) bool
}

// L7RuleParser takes the protobuf and converts the oneof relevant for the given L7 to an array
// of L7 rules. A packet matches if the 'Matches' method of any of these rules matches the
// 'l7' interface passed by the L7 implementation to PolicyMap.Matches() as the last parameter.
type L7RuleParser func(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule

// const after initialization
var l7RuleParsers map[string]L7RuleParser = make(map[string]L7RuleParser)

// RegisterL7Parser adds a l7 policy protocol protocol parser to the map of known l7 policy parsers.
// This is called from parser init() functions while we are still single-threaded
func RegisterL7RuleParser(l7PolicyTypeName string, parserFunc L7RuleParser) {
	log.Infof("NPDS: Registering L7 rule parser: %s", l7PolicyTypeName)
	l7RuleParsers[l7PolicyTypeName] = parserFunc
}

type PortNetworkPolicyRule struct {
	AllowedRemotes map[uint64]struct{}
	L7Rules        []L7NetworkPolicyRule
}

func newPortNetworkPolicyRule(config *cilium.PortNetworkPolicyRule) (PortNetworkPolicyRule, string, bool) {
	rule := PortNetworkPolicyRule{
		AllowedRemotes: make(map[uint64]struct{}, len(config.RemotePolicies)),
	}
	for _, remote := range config.GetRemotePolicies() {
		log.Debugf("NPDS::PortNetworkPolicyRule: Allowing remote %d", remote)
		rule.AllowedRemotes[remote] = struct{}{}
	}

	// Each parser registers a parsing function to parse it's L7 rules
	// The registered name must match 'l7_proto', if included in the message,
	// or one of the oneof type names
	l7Name := config.L7Proto
	if l7Name == "" {
		typeOf := reflect.TypeOf(config.L7)
		if typeOf != nil {
			l7Name = typeOf.Elem().Name()
		}
	}
	if l7Name != "" {
		l7Parser, ok := l7RuleParsers[l7Name]
		if ok {
			log.Debugf("NPDS::PortNetworkPolicyRule: Calling L7Parser %s on %v", l7Name, config.String())
			rule.L7Rules = l7Parser(config)
		} else {
			log.Debugf("NPDS::PortNetworkPolicyRule: Unknown L7 (%s), should drop everything.", l7Name)
		}
		// Unknown parsers are expected, bur will result in drop-all policy
		return rule, l7Name, ok
	}
	return rule, "", true // No L7 is ok
}

func (p *PortNetworkPolicyRule) Matches(remoteId uint32, l7 interface{}) bool {
	// Remote ID must match if we have any.
	if len(p.AllowedRemotes) > 0 {
		_, found := p.AllowedRemotes[uint64(remoteId)]
		if !found {
			return false
		}
	}
	if len(p.L7Rules) > 0 {
		for _, rule := range p.L7Rules {
			if rule.Matches(l7) {
				log.Debugf("NPDS::PortNetworkPolicyRule: L7 rule matches (%v)", p)
				return true
			}
		}
		return false
	}
	// Empty set matches any payload
	log.Debugf("NPDS::PortNetworkPolicyRule: Empty L7Rules matches (%v)", p)
	return true
}

type PortNetworkPolicyRules struct {
	Rules       []PortNetworkPolicyRule
	HaveL7Rules bool
}

func newPortNetworkPolicyRules(config []*cilium.PortNetworkPolicyRule) (PortNetworkPolicyRules, bool) {
	rules := PortNetworkPolicyRules{
		Rules:       make([]PortNetworkPolicyRule, 0, len(config)),
		HaveL7Rules: false,
	}
	if len(config) == 0 {
		log.Debugf("NPDS::PortNetworkPolicyRules: No rules, will allow everything.")
	}
	var firstTypeName string
	for _, rule := range config {
		newRule, typeName, ok := newPortNetworkPolicyRule(rule)
		if !ok {
			// Unknown L7 parser, must drop all traffic
			// Empty set of rules drops only when 'HaveL7Rules' is 'true'
			log.Debugf("NPDS::PortNetworkPolicyRules: Unknown L7 (%s), will drop everything.", typeName)
			return PortNetworkPolicyRules{HaveL7Rules: true}, false
		}
		if len(newRule.L7Rules) > 0 {
			rules.HaveL7Rules = true
		}
		if typeName != "" {
			if firstTypeName == "" {
				firstTypeName = typeName
			} else if typeName != firstTypeName {
				panic(fmt.Errorf("NPDS: Mismatching L7 types on the same port %v", config))
			}
		}
		rules.Rules = append(rules.Rules, newRule)
	}
	return rules, true
}

func (p *PortNetworkPolicyRules) Matches(remoteId uint32, l7 interface{}) bool {
	if !p.HaveL7Rules {
		// If there are no L7 rules, host proxy will not create a proxy redirect at all,
		// whereby the decicion made by the bpf datapath is final. Emulate the same behavior
		// in the sidecar by allowing such traffic.
		// TODO: This will need to be revised when non-bpf datapaths are to be supported.
		log.Debugf("NPDS::PortNetworkPolicyRules: No L7 rules; matches (%v)", p)
		return true
	}
	// Empty set matches any payload from anyone
	if len(p.Rules) == 0 {
		log.Debugf("NPDS::PortNetworkPolicyRules: No Rules; matches (%v)", p)
		return true
	}
	for _, rule := range p.Rules {
		if rule.Matches(remoteId, l7) {
			log.Debugf("NPDS::PortNetworkPolicyRules(remoteId=%d): rule matches (%v)", remoteId, p)
			return true
		}
	}
	return false
}

type PortNetworkPolicies struct {
	Rules map[uint32]PortNetworkPolicyRules
}

func newPortNetworkPolicies(config []*cilium.PortNetworkPolicy) PortNetworkPolicies {
	policy := PortNetworkPolicies{
		Rules: make(map[uint32]PortNetworkPolicyRules, len(config)),
	}
	for _, rule := range config {
		// Ignore UDP policies
		if rule.GetProtocol() == core.SocketAddress_UDP {
			continue
		}

		port := rule.GetPort()
		if _, found := policy.Rules[port]; found {
			panic(fmt.Errorf("NPDS: Duplicate port number %d in (rule: %v) (config: %v)", port, rule, config))
		}

		if rule.GetProtocol() != core.SocketAddress_TCP {
			panic(fmt.Errorf("NPDS: Invalid transport protocol %v", rule.GetProtocol()))
		}

		// Skip the port if not 'ok'
		rules, ok := newPortNetworkPolicyRules(rule.GetRules())
		if ok {
			log.Debugf("NPDS::PortNetworkPolicies(): installed TCP policy for port %d", port)
			policy.Rules[port] = rules
		} else {
			log.Debugf("NPDS::PortNetworkPolicies(): Skipped port due to unsupported L7: %d", port)
		}
	}
	return policy
}

func (p *PortNetworkPolicies) Matches(port, remoteId uint32, l7 interface{}) bool {
	rules, found := p.Rules[port]
	if found {
		if rules.Matches(remoteId, l7) {
			log.Debugf("NPDS::PortNetworkPolicies(port=%d, remoteId=%d): rule matches (%v)", port, remoteId, p)
			return true
		}
	}
	// No exact port match, try wildcard
	rules, foundWc := p.Rules[0]
	if foundWc {
		if rules.Matches(remoteId, l7) {
			log.Debugf("NPDS::PortNetworkPolicies(port=*, remoteId=%d): rule matches (%v)", remoteId, p)
			return true
		}
	}

	// No policy for the port was found. Cilium always creates a policy for redirects it
	// creates, so the host proxy never gets here. Sidecar gets all the traffic, which we need
	// to pass through since the bpf datapath already allowed it.
	// TODO: Change back to false only when non-bpf datapath is supported?

	//	log.Debugf("NPDS::PortNetworkPolicies(port=%d, remoteId=%d): allowing traffic on port for which there is no policy, assuming L3/L4 has passed it! (%v)", port, remoteId, p)
	//	return !(found || foundWc)
	if !(found || foundWc) {
		log.Debugf("NPDS::PortNetworkPolicies(port=%d, remoteId=%d): Dropping traffic on port for which there is no policy! (%v)", port, remoteId, p)
	}
	return false
}

type PolicyInstance struct {
	protobuf cilium.NetworkPolicy
	Ingress  PortNetworkPolicies
	Egress   PortNetworkPolicies
}

func newPolicyInstance(config *cilium.NetworkPolicy) *PolicyInstance {
	log.Debugf("NPDS::PolicyInstance: Inserting policy %s", config.String())

	return &PolicyInstance{
		protobuf: *config,
		Ingress:  newPortNetworkPolicies(config.GetIngressPerPortPolicies()),
		Egress:   newPortNetworkPolicies(config.GetEgressPerPortPolicies()),
	}
}

func (p *PolicyInstance) Matches(ingress bool, port, remoteId uint32, l7 interface{}) bool {
	if ingress {
		return p.Ingress.Matches(port, remoteId, l7)
	}
	return p.Egress.Matches(port, remoteId, l7)
}

// Network policies keyed by endpoint policy names
type PolicyMap map[string]*PolicyInstance

var policyMap atomic.Value // holds PolicyMap

func init() {
	setPolicyMap(newPolicyMap())
}

func newPolicyMap() PolicyMap {
	return make(PolicyMap)
}

func getPolicyMap() PolicyMap {
	return policyMap.Load().(PolicyMap)
}

func setPolicyMap(newMap PolicyMap) {
	policyMap.Store(newMap)
}

func PolicyMatches(endpointPolicyName string, ingress bool, port, remoteId uint32, l7 interface{}) bool {
	// Policy maps are never modified once published
	policy, found := getPolicyMap()[endpointPolicyName]
	if !found {
		log.Debugf("NPDS: Policy for %s not found (%v)", endpointPolicyName)
	}

	return found && policy.Matches(ingress, port, remoteId, l7)
}

// Used to serialize policy updates. Policy lookups do not need to take this.
var policyUpdateMutex lock.Mutex

// Update the PolicyMap from a protobuf. PolicyMap is only ever changed if the whole update is successful.
func PolicyUpdate(resp *envoy_api_v2.DiscoveryResponse) (err error) {
	policyUpdateMutex.Lock()
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); !ok {
				err = fmt.Errorf("NPDS: Panic: %v", r)
			}
		}
		policyUpdateMutex.Unlock()
	}()

	log.Debugf("NPDS: Updating policy from %v", resp)

	oldMap := getPolicyMap()
	newMap := newPolicyMap()

	for _, any := range resp.Resources {
		if any.TypeUrl != resp.TypeUrl {
			return fmt.Errorf("NPDS: Mismatching TypeUrls: %s != %s", any.TypeUrl, resp.TypeUrl)
		}
		var config cilium.NetworkPolicy
		if err = proto.Unmarshal(any.Value, &config); err != nil {
			return fmt.Errorf("NPDS: Policy unmarshal error: %v", err)
		}

		policyName := config.GetName()

		// Locate the old version, if any
		oldPolicy, found := oldMap[policyName]
		if found {
			// Check if the new policy is the same as the old one
			if proto.Equal(&config, &oldPolicy.protobuf) {
				log.Debugf("NPDS: New policy for %s is equal to the old one, no need to change", policyName)
				newMap[policyName] = oldPolicy
				continue
			}
		}

		// Validate new config
		if err = config.Validate(); err != nil {
			return fmt.Errorf("NPDS: Policy validation error for %s: %v", policyName, err)
		}

		// Create new PolicyInstance, may panic
		newMap[policyName] = newPolicyInstance(&config)
	}

	// Store the new policy map
	setPolicyMap(newMap)

	log.Debugf("NPDS: Policy Update completed: %v", newMap)
	return
}
