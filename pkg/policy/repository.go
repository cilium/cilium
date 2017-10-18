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

package policy

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"

	log "github.com/sirupsen/logrus"
)

// Repository is a list of policy rules which in combination form the security
// policy. A policy repository can be
type Repository struct {
	// Mutex protects the whole policy tree
	Mutex lock.RWMutex
	rules []*rule

	// revision is the revision of the policy repository. It will be
	// incremented whenever the policy repository is changed
	revision uint64
}

// NewPolicyRepository allocates a new policy repository
func NewPolicyRepository() *Repository {
	return &Repository{}
}

// traceState is an internal structure used to collect information
// while determining policy decision
type traceState struct {
	// selectedRules is the number of rules with matching EndpointSelector
	selectedRules int

	// matchedRules is the number of rules that have allowed traffic
	matchedRules int

	// constrainedRules counts how many "FromRequires" constraints are
	// unsatisfied
	constrainedRules int

	// ruleID is the rule ID currently being evaluated
	ruleID int
}

func (state *traceState) trace(p *Repository, ctx *SearchContext) {
	ctx.PolicyTrace("%d/%d rules selected\n", state.selectedRules, len(p.rules))
	if state.constrainedRules > 0 {
		ctx.PolicyTrace("Found unsatisfied FromRequires constraint\n")
	} else if state.matchedRules > 0 {
		ctx.PolicyTrace("Found allow rule\n")
	} else {
		ctx.PolicyTrace("Found no allow rule\n")
	}
}

// CanReachRLocked evaluates the policy repository for the provided search
// context and returns the verdict or api.Undecided if no rule matches. The
// policy repository mutex must be held.
func (p *Repository) CanReachRLocked(ctx *SearchContext) api.Decision {
	decision := api.Undecided
	state := traceState{}

loop:
	for i, r := range p.rules {
		state.ruleID = i
		switch r.canReach(ctx, &state) {
		// The rule contained a constraint which was not met, this
		// connection is not allowed
		case api.Denied:
			decision = api.Denied
			break loop

		// The rule allowed the connection but a later rule may impose
		// additional constraints, so we store the decision but allow
		// it to be overwritten by an additional requirement
		case api.Allowed:
			decision = api.Allowed
		}
	}

	state.trace(p, ctx)

	return decision
}

// AllowsLabelAccess evaluates the policy repository for the provided search
// context and returns the verdict. If no matching policy allows for the
// connection, the request will be denied. The policy repository mutex must be
// held.
func (p *Repository) AllowsLabelAccess(ctx *SearchContext) api.Decision {
	ctx.PolicyTrace("Tracing %s\n", ctx.String())
	decision := api.Denied

	if len(p.rules) == 0 {
		ctx.PolicyTrace("  No rules found\n")
	} else {
		if p.CanReachRLocked(ctx) == api.Allowed {
			decision = api.Allowed
		}
	}

	ctx.PolicyTrace("Label verdict: %s", decision.String())

	return decision
}

// ResolveL4Policy resolves the L4 policy for a set of endpoints by searching
// the policy repository for `PortRule` rules that are attached to a `Rule`
// where the EndpointSelector matches `ctx.To`. `ctx.From` takes no effect and
// is ignored in the search.  If multiple `PortRule` rules are found, all rules
// are merged together. If rules contains overlapping port definitions, the first
// rule found in the repository takes precedence.
//
// TODO: Coalesce l7 rules?
func (p *Repository) ResolveL4Policy(ctx *SearchContext) (*L4Policy, error) {
	result := NewL4Policy()

	ctx.PolicyTrace("\n")
	if ctx.EgressL4Only {
		ctx.PolicyTrace("Resolving egress port policy for %+v\n", ctx.To)
	} else if ctx.IngressL4Only {
		ctx.PolicyTrace("Resolving ingress port policy for %+v\n", ctx.To)
	} else {
		ctx.PolicyTrace("Resolving port policy for %+v\n", ctx.To)
	}

	state := traceState{}
	for _, r := range p.rules {
		found, err := r.resolveL4Policy(ctx, &state, result)
		if err != nil {
			return nil, err
		}
		state.ruleID++
		if found != nil {
			state.matchedRules++
		}
	}

	state.trace(p, ctx)
	return result, nil
}

// ResolveL3Policy resolves the L3 policy for a set of endpoints by searching
// the policy repository for `CIDR` rules that are attached to a `Rule`
// where the EndpointSelector matches `ctx.To`. `ctx.From` takes no effect and
// is ignored in the search.
func (p *Repository) ResolveL3Policy(ctx *SearchContext) *L3Policy {
	result := NewL3Policy()

	ctx.PolicyTrace("Resolving L3 (CIDR) policy for %+v\n", ctx.To)

	state := traceState{}
	for _, r := range p.rules {
		r.resolveL3Policy(ctx, &state, result)
		state.ruleID++
	}

	state.trace(p, ctx)
	return result
}

func (p *Repository) allowsL4Egress(searchCtx *SearchContext) api.Decision {
	ctx := *searchCtx
	ctx.To = ctx.From
	ctx.From = labels.LabelArray{}
	ctx.EgressL4Only = true

	policy, err := p.ResolveL4Policy(&ctx)
	if err != nil {
		log.WithError(err).Warn("Evaluation error while resolving L4 egress policy")
	}
	verdict := api.Undecided
	if err == nil && len(policy.Egress) > 0 {
		verdict = policy.EgressCoversDPorts(ctx.DPorts)
	}

	if len(ctx.DPorts) == 0 {
		ctx.PolicyTrace("L4 egress verdict: [no port context specified]")
	} else {
		ctx.PolicyTrace("L4 egress verdict: %s", verdict.String())
	}

	return verdict
}

func (p *Repository) allowsL4Ingress(ctx *SearchContext) api.Decision {
	ctx.IngressL4Only = true

	policy, err := p.ResolveL4Policy(ctx)
	if err != nil {
		log.WithError(err).Warn("Evaluation error while resolving L4 ingress policy")
	}
	verdict := api.Undecided
	if err == nil && len(policy.Ingress) > 0 {
		verdict = policy.IngressCoversContext(ctx)
	}

	if len(ctx.DPorts) == 0 {
		ctx.PolicyTrace("L4 ingress verdict: [no port context specified]")
	} else {
		ctx.PolicyTrace("L4 ingress verdict: %s", verdict.String())
	}

	return verdict
}

// AllowsRLocked evaluates the policy repository for the provided search
// context and returns the verdict. If no matching policy allows for the
// connection, the request will be denied. The policy repository mutex must be
// held.
func (p *Repository) AllowsRLocked(ctx *SearchContext) api.Decision {
	ctx.PolicyTrace("Tracing %s\n", ctx.String())
	decision := p.CanReachRLocked(ctx)
	ctx.PolicyTrace("Label verdict: %s", decision.String())
	if decision == api.Allowed {
		return decision
	}

	// We only report the overall decision as L4 inclusive if a port has
	// been specified
	if len(ctx.DPorts) != 0 {
		l4Egress := p.allowsL4Egress(ctx)
		l4Ingress := p.allowsL4Ingress(ctx)

		// Explicit deny should deny; Allow+Undecided should allow
		if l4Egress == api.Denied || l4Ingress == api.Denied {
			decision = api.Denied
		} else if l4Egress == api.Allowed || l4Ingress == api.Allowed {
			decision = api.Allowed
		}
	}

	if decision != api.Allowed {
		decision = api.Denied
	}
	return decision
}

// SearchRLocked searches the policy repository for rules which match the
// specified labels and will return an array of all rules which matched.
func (p *Repository) SearchRLocked(labels labels.LabelArray) api.Rules {
	result := api.Rules{}

	for _, r := range p.rules {
		if r.Labels.Contains(labels) {
			result = append(result, &r.Rule)
		}
	}

	return result
}

// Add inserts a rule into the policy repository
func (p *Repository) Add(r api.Rule) (uint64, error) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()

	realRule := &rule{Rule: r}
	if err := realRule.sanitize(); err != nil {
		return p.revision, err
	}

	p.rules = append(p.rules, realRule)
	p.revision++

	return p.revision, nil
}

// AddListLocked inserts a rule into the policy repository with the repository already locked
func (p *Repository) AddListLocked(rules api.Rules) (uint64, error) {
	// Validate entire rule list first and only append array if
	// all rules are valid
	newList := make([]*rule, len(rules))
	for i := range rules {
		newList[i] = &rule{Rule: *rules[i]}
		if err := newList[i].sanitize(); err != nil {
			return p.revision, err
		}
	}

	p.rules = append(p.rules, newList...)
	p.revision++

	return p.revision, nil
}

// AddList inserts a rule into the policy repository
func (p *Repository) AddList(rules api.Rules) (uint64, error) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.AddListLocked(rules)
}

// DeleteByLabelsLocked deletes all rules in the policy repository which
// contain the specified labels
func (p *Repository) DeleteByLabelsLocked(labels labels.LabelArray) (uint64, int) {
	deleted := 0
	new := p.rules[:0]

	for _, r := range p.rules {
		if !r.Labels.Contains(labels) {
			new = append(new, r)
		} else {
			deleted++
		}
	}

	if deleted > 0 {
		p.revision++
		p.rules = new
	}

	return p.revision, deleted
}

// DeleteByLabels deletes all rules in the policy repository which contain the
// specified labels
func (p *Repository) DeleteByLabels(labels labels.LabelArray) (uint64, int) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.DeleteByLabelsLocked(labels)
}

// JSONMarshalRules returns a slice of policy rules as string in JSON
// representation
func JSONMarshalRules(rules api.Rules) string {
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// GetJSON returns all rules of the policy repository as string in JSON
// representation
func (p *Repository) GetJSON() string {
	p.Mutex.RLock()
	defer p.Mutex.RUnlock()

	result := api.Rules{}
	for _, r := range p.rules {
		result = append(result, &r.Rule)
	}

	return JSONMarshalRules(result)
}

// GetRulesMatching returns whether any of the rules in a repository contain a
// rule with labels matching the labels in the provided LabelArray.
//
// Must be called with p.Mutex held
func (p *Repository) GetRulesMatching(labels labels.LabelArray, includeEntities bool) bool {

	for _, r := range p.rules {
		rulesMatch := r.EndpointSelector.Matches(labels)
		if rulesMatch {
			return true
		}

		if includeEntities && len(r.toEntities)+len(r.fromEntities) > 0 {
			return true
		}
	}
	return false
}

// NumRules returns the amount of rules in the policy repository.
//
// Must be called with p.Mutex held
func (p *Repository) NumRules() int {
	return len(p.rules)
}

// GetRevision returns the revision of the policy repository
func (p *Repository) GetRevision() uint64 {
	return p.revision
}

// ConvertToK8sServiceToToCIDR traverses all egress rules and matches them against provided serviceInfo. If a matching egress rule is found it is populated with ToCIDR and ToPorts entries based on endpoint object.
func (p *Repository) ConvertToK8sServiceToToCIDR(serviceInfo types.K8sServiceNamespace, endpoint types.K8sServiceEndpoint) error {
	for _, rule := range p.rules {
		for index, egress := range rule.Egress {
			for _, service := range egress.ToServices {
				// TODO: match services by labels
				if service.K8sService == serviceInfo {
					if err := generateToCidrFromEndpoint(&rule.Egress[index], endpoint); err != nil {
						return err
					}
					if err := generateToPortsFromEndpoint(&rule.Egress[index], endpoint); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// generateToCidrFromEndpoint takes an egress rule and populates it with ToCIDR rules based on provided enpoint object
func generateToCidrFromEndpoint(egress *api.EgressRule, endpoint types.K8sServiceEndpoint) error {
	for ip := range endpoint.BEIPs {
		epIP := net.ParseIP(ip)
		// TODO: this will only work for IPv4. How to retrieve the mask from IPv6 address?
		mask := epIP.DefaultMask()

		found := false
		for _, c := range egress.ToCIDR {
			_, cidr, err := net.ParseCIDR(string(c))
			if err != nil {
				return err
			}
			if cidr.Contains(epIP) {
				found = true
				break
			}
		}
		if !found {
			cidr := net.IPNet{IP: epIP.Mask(mask), Mask: mask}
			egress.ToCIDR = append(egress.ToCIDR, api.CIDR(cidr.String()))
		}
	}

	return nil
}

// generateToPortsFromEndpoint takes an egress rule and populates it with ToPorts rules based on provided enpoint object
func generateToPortsFromEndpoint(egress *api.EgressRule, endpoint types.K8sServiceEndpoint) error {
	// additional port rule that will contain all endpoint ports
	portRule := api.PortRule{}
	for _, port := range endpoint.Ports {
		found := false
	loop:
		for _, portRule := range egress.ToPorts {
			for _, portProtocol := range portRule.Ports {
				numericPort, err := strconv.Atoi(portProtocol.Port)
				if err != nil {
					return err
				}

				if strings.ToLower(string(port.Protocol)) == strings.ToLower(string(portProtocol.Protocol)) && int(port.Port) == numericPort {
					found = true
					break loop
				}
			}
		}
		if !found {
			portRule.Ports = append(portRule.Ports, api.PortProtocol{
				Port:     strconv.Itoa(int(port.Port)),
				Protocol: api.L4Proto(strings.ToUpper(string(port.Protocol))),
			})
		}
	}

	if len(portRule.Ports) > 0 {
		egress.ToPorts = append(egress.ToPorts, portRule)
	}

	return nil
}

// DeleteEndpointGeneratedEgressRules traverses all egress rules, matches them against provided service info and deletes ToCIDR and ToPorts entries that match provided endpoint
func (p *Repository) DeleteEndpointGeneratedEgressRules(serviceInfo types.K8sServiceNamespace, endpoint types.K8sServiceEndpoint) error {
	for policyRuleIndex, rule := range p.rules {
		for egressIndex, egress := range rule.Egress {
			for _, service := range egress.ToServices {
				// TODO: match services by labels
				if service.K8sService == serviceInfo {
					if err := deleteToCidrFromEndpoint(&p.rules[policyRuleIndex].Egress[egressIndex], endpoint); err != nil {
						return err
					}
					if err := deleteToPortsFromEndpoint(&p.rules[policyRuleIndex].Egress[egressIndex], endpoint); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// deleteToCidrFromEndpoint takes an egress rule and removes ToCIDR rules matching endpoint
func deleteToCidrFromEndpoint(egress *api.EgressRule, endpoint types.K8sServiceEndpoint) error {
	newToCIDR := make([]api.CIDR, 0, len(egress.ToCIDR))

	for ip := range endpoint.BEIPs {
		epIP := net.ParseIP(ip)
		for _, c := range egress.ToCIDR {
			_, cidr, err := net.ParseCIDR(string(c))
			if err != nil {
				return err
			}
			if !cidr.Contains(epIP) {
				//if endpoint is not in CIDR it's ok to retain it
				newToCIDR = append(newToCIDR, c)
			}
		}
	}

	egress.ToCIDR = newToCIDR

	return nil
}

// deleteToPortsFromEndpoint takes an egress rule and removes ToPorts rules matching endpoint
func deleteToPortsFromEndpoint(egress *api.EgressRule, endpoint types.K8sServiceEndpoint) error {
	newPortRules := make([]api.PortRule, 0, len(egress.ToPorts))

	for _, port := range endpoint.Ports {
		for _, portRule := range egress.ToPorts {
			for _, portProtocol := range portRule.Ports {
				numericPort, err := strconv.Atoi(portProtocol.Port)
				if err != nil {
					return err
				}

				if !(strings.ToLower(string(port.Protocol)) == strings.ToLower(string(portProtocol.Protocol)) && int(port.Port) == numericPort) {
					newPortRules = append(newPortRules, portRule)
				}
			}
		}
	}

	egress.ToPorts = newPortRules

	return nil
}
