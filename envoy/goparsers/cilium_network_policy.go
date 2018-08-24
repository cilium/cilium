package main

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"

	"github.com/golang/protobuf/proto"

	log "github.com/sirupsen/logrus"
)

// Each L7 rule implements this interface
type L7NetworkPolicyRule interface {
	Matches(interface{}) bool
}

// L7RuleParser takes the protobuf and converts the oneof relevant for the given L7 to an array
// of L7 rules. A packet matches if the 'Matches' method of any of these rules matches the
// 'l7' interface passed by the L7 implementation to PolicyMap.Matches() as the last parameter.
type L7RuleParser func(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule

var L7RuleParsers map[string]L7RuleParser // const after initialization

// RegisterL7Parser adds a l7 policy protocol protocol parser to the map of known l7 policy parsers.
// This is called from parser init() functions while we are still single-threaded
func RegisterL7RuleParser(l7PolicyTypeName string, parserFunc L7RuleParser) {
	if L7RuleParsers == nil { // init on first call
		L7RuleParsers = make(map[string]L7RuleParser)
	}
	log.Infof("RegisterL7RuleParser: Registering L7 rule parser: %v", l7PolicyTypeName)
	L7RuleParsers[l7PolicyTypeName] = parserFunc
}

type PortNetworkPolicyRule struct {
	AllowedRemotes map[uint64]struct{}
	L7Rules        []L7NetworkPolicyRule
}

func newPortNetworkPolicyRule(config *cilium.PortNetworkPolicyRule) PortNetworkPolicyRule {
	rule := PortNetworkPolicyRule{
		AllowedRemotes: make(map[uint64]struct{}, len(config.RemotePolicies)),
	}
	for _, remote := range config.GetRemotePolicies() {
		log.Infof("PortNetworkPolicyRule: Allowing remote %d", remote)
		rule.AllowedRemotes[remote] = struct{}{}
	}

	// Each parser registers a parsing function to parse it's L7 rules
	l7Name := reflect.TypeOf(config.L7Rules).Elem().Name()
	l7Parser, ok := L7RuleParsers[l7Name]
	if !ok {
		panic(fmt.Errorf("L7 Parser not found: %s", l7Name))
	}
	rule.L7Rules = l7Parser(config)

	return rule
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
				log.Infof("PortNetworkPolicyRule: L7 rule matches (%v)", p)
				return true
			}
		}
		return false
	}
	// Empty set matches any payload
	log.Infof("PortNetworkPolicyRule: Empty L7Rules matches (%v)", p)
	return true
}

type PortNetworkPolicyRules struct {
	Rules       []PortNetworkPolicyRule
	HaveL7Rules bool
}

func newPortNetworkPolicyRules(config []*cilium.PortNetworkPolicyRule) PortNetworkPolicyRules {
	rules := PortNetworkPolicyRules{
		Rules:       make([]PortNetworkPolicyRule, 0, len(config)),
		HaveL7Rules: false,
	}
	if len(config) == 0 {
		log.Infof("PortNetworkPolicyRules: No rules, will allow everything.")
	}
	for idx, rule := range config {
		newRule := newPortNetworkPolicyRule(rule)
		if len(newRule.L7Rules) > 0 {
			rules.HaveL7Rules = true
		}
		rules.Rules = rules.Rules[:idx+1] // Increase slice len
		rules.Rules[idx] = newRule
	}
	return rules
}

func (p *PortNetworkPolicyRules) Matches(remoteId uint32, l7 interface{}) bool {
	if !p.HaveL7Rules {
		// If there are no L7 rules, host proxy will not create a proxy redirect at all,
		// whereby the decicion made by the bpf datapath is final. Emulate the same behavior
		// in the sidecar by allowing such traffic.
		// TODO: This will need to be revised when non-bpf datapaths are to be supported.
		log.Infof("PortNetworkPolicyRules: No L7 rules; matches (%v)", p)
		return true
	}
	// Empty set matches any payload from anyone
	if len(p.Rules) == 0 {
		log.Infof("PortNetworkPolicyRules: No Rules; matches (%v)", p)
		return true
	}
	for _, rule := range p.Rules {
		if rule.Matches(remoteId, l7) {
			log.Infof("PortNetworkPolicyRules(remoteId=%d): rule matches (%v)", remoteId, p)
			return true
		}
	}
	return false
}

type PortNetworkPolicy struct {
	Rules map[uint32]PortNetworkPolicyRules
}

func newPortNetworkPolicy(config []*cilium.PortNetworkPolicy) PortNetworkPolicy {
	policy := PortNetworkPolicy{
		Rules: make(map[uint32]PortNetworkPolicyRules, len(config)),
	}
	for _, rule := range config {
		port := rule.GetPort()
		if _, found := policy.Rules[port]; found {
			panic(fmt.Errorf("PortNetworkPolicy: Duplicate port number %d", port))
		}

		switch rule.GetProtocol() {
		case core.SocketAddress_TCP:
			log.Infof("Cilium L7 PortNetworkPolicy(): installing TCP policy for port %d", port)
			policy.Rules[port] = newPortNetworkPolicyRules(rule.GetRules())
		}
	}
	return policy
}

func (p *PortNetworkPolicy) Matches(port, remoteId uint32, l7 interface{}) bool {
	rules, found := p.Rules[port]
	if found {
		if rules.Matches(remoteId, l7) {
			log.Infof("PortNetworkPolicy(port=%d, remoteId=%d): rule matches (%v)", port, remoteId, p)
			return true
		}
	}
	// No exact port match, try wildcard
	rules, foundWc := p.Rules[0]
	if foundWc {
		if rules.Matches(remoteId, l7) {
			log.Infof("PortNetworkPolicy(port=*, remoteId=%d): rule matches (%v)", remoteId, p)
			return true
		}
	}

	// No policy for the port was found. Cilium always creates a policy for redirects it
	// creates, so the host proxy never gets here. Sidecar gets all the traffic, which we need
	// to pass through since the bpf datapath already allowed it.
	// TODO: Change back to false only when non-bpf datapath is supported?

	//	log.Infof("PortNetworkPolicy(port=%d, remoteId=%d): allowing traffic on port for which there is no policy, assuming L3/L4 has passed it! (%v)", port, remoteId, p)
	//	return !(found || foundWc)
	if !(found || foundWc) {
		log.Infof("PortNetworkPolicy(port=%d, remoteId=%d): Dropping traffic on port for which there is no policy! (%v)", port, remoteId, p)
	}
	return false
}

type PolicyInstance struct {
	protobuf cilium.NetworkPolicy
	Ingress  PortNetworkPolicy
	Egress   PortNetworkPolicy
}

func newPolicyInstance(config *cilium.NetworkPolicy) *PolicyInstance {
	return &PolicyInstance{
		protobuf: *config,
		Ingress:  newPortNetworkPolicy(config.GetIngressPerPortPolicies()),
		Egress:   newPortNetworkPolicy(config.GetEgressPerPortPolicies()),
	}
}

func (p *PolicyInstance) Matches(ingress bool, port, remoteId uint32, l7 interface{}) bool {
	if ingress {
		return p.Ingress.Matches(port, remoteId, l7)
	}
	return p.Egress.Matches(port, remoteId, l7)
}

type PolicyMap struct {
	mutex    sync.RWMutex
	policies map[string]*PolicyInstance
}

func NewPolicyMap() PolicyMap {
	return PolicyMap{
		policies: make(map[string]*PolicyInstance),
	}
}

func (p *PolicyMap) Matches(endpointPolicyName string, ingress bool, port, remoteId uint32, l7 interface{}) bool {
	p.mutex.RLock()
	policy, found := p.policies[endpointPolicyName]
	// Policy instances are never modified once placed into the map, so we can release the lock here.
	p.mutex.RUnlock()

	if !found {
		log.Infof("Policy for %s not found", endpointPolicyName)
	}

	return found && policy.Matches(ingress, port, remoteId, l7)
}

// ConfigUpdate updates a PolicyInstance.
// Only one updater is assimed to be running at any time.
func (p *PolicyMap) Upsert(config *cilium.NetworkPolicy) {
	policyName := config.GetName()

	// Locate the old version, if any
	p.mutex.RLock()
	oldPolicy, found := p.policies[policyName]
	// Policy instances are never modified once placed into the map, so we can release the lock here.
	p.mutex.RUnlock()

	if found {
		// Check if the new policy is the same as the old one
		if proto.Equal(config, &oldPolicy.protobuf) {
			log.Errorf("New policy for %s is equal to the old one, no need to change", policyName)
			return
		}
	}

	// Validate new config
	if err := config.Validate(); err != nil {
		panic(fmt.Errorf("Policy validation error for %s: %v", policyName, err))
	}

	// Create new PolicyInstance
	newPolicy := newPolicyInstance(config)

	// Swap it in place of the old one.
	// A parallel goroutines may be completing a Match using the old version
	p.mutex.Lock()
	p.policies[policyName] = newPolicy
	p.mutex.Unlock()
}

func (p *PolicyMap) Update(resp *envoy_api_v2.DiscoveryResponse) (err error) {
	log.Infof("Updating policy from %v", resp)

	defer func() {
		if err, ok := recover().(error); ok {
			log.Errorf("Policy Update failed: %v", err)
		}
	}()

	// Get the list of current policies
	p.mutex.RLock()
	policyNames := make(map[string]struct{}, len(p.policies))
	for k := range p.policies {
		policyNames[k] = struct{}{}
	}
	p.mutex.RUnlock()

	for _, any := range resp.Resources {
		if any.TypeUrl != resp.TypeUrl {
			panic(fmt.Errorf("Mismatching TypeUrls: %s != %s", any.TypeUrl, resp.TypeUrl))
		}
		var config cilium.NetworkPolicy
		if err = proto.Unmarshal(any.Value, &config); err != nil {
			panic(err)
		}
		p.Upsert(&config)
		delete(policyNames, config.GetName()) // mark as updated
	}

	// remove all non-updated policyNames
	for k, v := range policyNames {
		p.mutex.Lock()
		delete(p.policies, k)
		p.mutex.Unlock()
		log.Infof("Deleted old policy %s = %v", k, v)
	}

	log.Infof("Policy Update completed: %v", p.policies)
	return nil
}

// func start() {
//	go func() {
//		conn, err := grpc.Dial(*serverAddr)
//		if err != nil {
//			...
//		}
//		defer conn.Close()
//	}
//}
