// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

var _ policy.Translator = RuleTranslator{}

// RuleTranslator implements pkg/policy.Translator interface
// Translate populates/depopulates given rule with ToCIDR rules
// Based on provided service/endpoint
type RuleTranslator struct {
	Service          ServiceID
	Endpoint         Endpoints
	ServiceLabels    map[string]string
	Revert           bool
	AllocatePrefixes bool
}

// Translate calls TranslateEgress on all r.Egress rules
func (k RuleTranslator) Translate(r *api.Rule, result *policy.TranslationResult) error {
	for egressIndex := range r.Egress {
		err := k.TranslateEgress(&r.Egress[egressIndex], result)
		if err != nil {
			return err
		}
	}
	return nil
}

// TranslateEgress populates/depopulates egress rules with ToCIDR entries based
// on toService entries
func (k RuleTranslator) TranslateEgress(r *api.EgressRule, result *policy.TranslationResult) error {

	defer r.SetAggregatedSelectors()
	err := k.depopulateEgress(r, result)
	if err != nil {
		return err
	}
	if !k.Revert {
		err := k.populateEgress(r, result)
		if err != nil {
			return err
		}
	}
	return nil
}

func (k RuleTranslator) populateEgress(r *api.EgressRule, result *policy.TranslationResult) error {
	for _, service := range r.ToServices {
		if k.serviceMatches(service) {
			if backendPrefixes, err := k.generateToCidrFromEndpoint(r, k.Endpoint, k.AllocatePrefixes); err != nil {
				return err
			} else {
				result.PrefixesToAdd = append(result.PrefixesToAdd, backendPrefixes...)
			}
			// TODO: generateToPortsFromEndpoint when ToPorts and ToCIDR are compatible
		}
	}
	return nil
}

func (k RuleTranslator) depopulateEgress(r *api.EgressRule, result *policy.TranslationResult) error {
	for _, service := range r.ToServices {
		// NumToServicesRules are only counted in depopulate to avoid
		// counting rules twice
		result.NumToServicesRules++
		if k.serviceMatches(service) {
			if prefixesToRelease, err := k.deleteToCidrFromEndpoint(r, k.Endpoint, k.AllocatePrefixes); err != nil {
				return err
			} else {
				result.PrefixesToRelease = append(result.PrefixesToRelease, prefixesToRelease...)
			}
			// TODO: generateToPortsFromEndpoint when ToPorts and ToCIDR are compatible
		}
	}
	return nil
}

func (k RuleTranslator) serviceMatches(service api.Service) bool {
	if service.K8sServiceSelector != nil {
		es := api.EndpointSelector(service.K8sServiceSelector.Selector)
		es.SyncRequirementsWithLabelSelector()
		esMatches := es.Matches(labels.Set(k.ServiceLabels))
		return esMatches &&
			(service.K8sServiceSelector.Namespace == k.Service.Namespace || service.K8sServiceSelector.Namespace == "")
	}

	if service.K8sService != nil {
		return service.K8sService.ServiceName == k.Service.Name &&
			(service.K8sService.Namespace == k.Service.Namespace || service.K8sService.Namespace == "")
	}

	return false
}

// generateToCidrFromEndpoint takes an egress rule and populates it with
// ToCIDR rules based on provided endpoint object
func (k RuleTranslator) generateToCidrFromEndpoint(
	egress *api.EgressRule,
	endpoint Endpoints,
	allocatePrefixes bool) ([]*net.IPNet, error) {

	var prefixes []*net.IPNet
	var err error
	// allocatePrefixes if true here implies that this translation is
	// occurring after policy import. This means that the CIDRs were not
	// known at that time, so the IPCache hasn't been informed about them.
	// In this case, it's the job of this Translator to notify the IPCache.
	if allocatePrefixes {
		prefixes, err = endpoint.CIDRPrefixes()
		if err != nil {
			return nil, err
		}
	}

	// This will generate one-address CIDRs consisting of endpoint backend ip
	mask := net.CIDRMask(128, 128)
	for addrCluster := range endpoint.Backends {
		ipStr := addrCluster.Addr().String()

		epIP := net.ParseIP(ipStr)
		if epIP == nil {
			return nil, fmt.Errorf("unable to parse ip: %s", ipStr)
		}

		found := false
		for _, c := range egress.ToCIDRSet {
			_, cidr, err := net.ParseCIDR(string(c.Cidr))
			if err != nil {
				return nil, err
			}
			if cidr.Contains(epIP) {
				found = true
				break
			}
		}
		if !found {
			cidr := net.IPNet{IP: epIP.Mask(mask), Mask: mask}
			egress.ToCIDRSet = append(egress.ToCIDRSet, api.CIDRRule{
				Cidr:      api.CIDR(cidr.String()),
				Generated: true,
			})
		}
	}
	return prefixes, nil
}

// deleteToCidrFromEndpoint takes an egress rule and removes ToCIDR rules
// matching endpoint. Returns an error if any of the backends are malformed.
//
// If all backends are valid, attempts to remove any ipcache CIDR mappings (and
// CIDR Identities) from the kvstore for backends in 'endpoint' that are being
// removed from the policy. On failure to release such kvstore mappings, errors
// will be logged but this function will return nil to allow subsequent
// processing to proceed.
func (k RuleTranslator) deleteToCidrFromEndpoint(
	egress *api.EgressRule,
	endpoint Endpoints,
	releasePrefixes bool) ([]*net.IPNet, error) {

	var toReleasePrefixes []*net.IPNet
	delCIDRRules := make(map[int]*api.CIDRRule, len(egress.ToCIDRSet))

	for addrCluster := range endpoint.Backends {
		ipStr := addrCluster.Addr().String()

		epIP := net.ParseIP(ipStr)
		if epIP == nil {
			return nil, fmt.Errorf("unable to parse ip: %s", ipStr)
		}

		for i, c := range egress.ToCIDRSet {
			if _, ok := delCIDRRules[i]; ok {
				// it's already going to be deleted so we can continue
				continue
			}
			_, cidr, err := net.ParseCIDR(string(c.Cidr))
			if err != nil {
				return nil, err
			}
			// delete all generated CIDRs for a CIDR that match the given
			// endpoint
			if c.Generated && cidr.Contains(epIP) {
				delCIDRRules[i] = &egress.ToCIDRSet[i]
			}
		}
		if len(delCIDRRules) == len(egress.ToCIDRSet) {
			break
		}
	}

	// If no rules were deleted we can do an early return here and avoid doing
	// the useless operations below.
	if len(delCIDRRules) == 0 {
		return toReleasePrefixes, nil
	}

	if releasePrefixes {
		delSlice := make([]api.CIDRRule, 0, len(egress.ToCIDRSet))
		for _, delCIDRRule := range delCIDRRules {
			delSlice = append(delSlice, *delCIDRRule)
		}
		toReleasePrefixes = policy.GetPrefixesFromCIDRSet(delSlice)
	}

	// if endpoint is not in CIDR or it's not generated it's ok to retain it
	newCIDRRules := make([]api.CIDRRule, 0, len(egress.ToCIDRSet)-len(delCIDRRules))
	for i, c := range egress.ToCIDRSet {
		// If the rule was deleted then it shouldn't be re-added
		if _, ok := delCIDRRules[i]; ok {
			continue
		}
		newCIDRRules = append(newCIDRRules, c)
	}

	egress.ToCIDRSet = newCIDRRules

	return toReleasePrefixes, nil
}

// PreprocessRules translates rules that apply to headless services
func PreprocessRules(r api.Rules, cache *ServiceCache, ipcache *ipcache.IPCache) error {

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	for _, rule := range r {
		// Translate only handles egress rules
		if rule.Egress == nil {
			continue
		}
		for ns, ep := range cache.endpoints {
			svc, ok := cache.services[ns]
			if ok && svc.IsExternal() {
				eps := ep.GetEndpoints()
				if eps != nil {
					t := NewK8sTranslator(ipcache, ns, *eps, false, svc.Labels, false)
					// We don't need to check the translation result here because the k8s
					// RuleTranslator above sets allocatePrefixes to be false.
					err := t.Translate(rule, &policy.TranslationResult{})
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// NewK8sTranslator returns RuleTranslator.
// If allocatePrefixes is set to true, then translation calls will return
// prefixes that need to be allocated or deallocated.
func NewK8sTranslator(
	ipcache *ipcache.IPCache,
	serviceInfo ServiceID,
	endpoint Endpoints,
	revert bool,
	labels map[string]string,
	allocatePrefixes bool) RuleTranslator {
	return RuleTranslator{
		Service:          serviceInfo,
		Endpoint:         endpoint,
		ServiceLabels:    labels,
		Revert:           revert,
		AllocatePrefixes: allocatePrefixes,
	}
}
