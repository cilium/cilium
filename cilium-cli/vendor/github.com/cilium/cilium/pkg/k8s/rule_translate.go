// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/slices"
)

var _ policy.Translator = RuleTranslator{}

// RuleTranslator implements pkg/policy.Translator interface
// Translate populates/depopulates given rule with ToCIDR rules
// Based on provided service/endpoint
type RuleTranslator struct {
	Service                  ServiceID
	OldEndpoint, NewEndpoint Endpoints
	ServiceLabels            map[string]string
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

	err = k.populateEgress(r, result)
	if err != nil {
		return err
	}

	if len(result.PrefixesToAdd) > 0 || len(result.PrefixesToRelease) > 0 {
		release := slices.Diff(result.PrefixesToRelease, result.PrefixesToAdd)
		add := slices.Diff(result.PrefixesToAdd, result.PrefixesToRelease)
		result.PrefixesToRelease = release
		result.PrefixesToAdd = add
	}
	return nil
}

func (k RuleTranslator) populateEgress(r *api.EgressRule, result *policy.TranslationResult) error {
	for _, service := range r.ToServices {
		if k.serviceMatches(service) {
			if backendPrefixes, err := k.generateToCidrFromEndpoint(r, k.NewEndpoint); err != nil {
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
			if prefixesToRelease, err := k.deleteToCidrFromEndpoint(r, k.OldEndpoint); err != nil {
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
	endpoints Endpoints,
) ([]netip.Prefix, error) {
	prefixes := endpoints.Prefixes()

	// This will generate one-address CIDRs consisting of endpoint backend ip
	for addrCluster := range endpoints.Backends {
		epIP := addrCluster.Addr()

		found := false
		for _, c := range egress.ToCIDRSet {
			prefix, err := netip.ParsePrefix(string(c.Cidr))
			if err != nil {
				return nil, err
			}
			if prefix.Contains(epIP) {
				found = true
				break
			}
		}
		if !found {
			mask := 32
			if epIP.Is6() {
				mask = 128
			}
			cidr := netip.PrefixFrom(epIP, mask)
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
// If all backends are valid, returns any CIDR mappings that are being removed
// from the policy. The caller must attempt to release this via the IPCache
// identity release functions.
func (k RuleTranslator) deleteToCidrFromEndpoint(
	egress *api.EgressRule,
	endpoints Endpoints,
) ([]netip.Prefix, error) {

	var toReleasePrefixes []netip.Prefix
	delCIDRRules := make(map[int]*api.CIDRRule, len(egress.ToCIDRSet))

	for addrCluster := range endpoints.Backends {
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

	delSlice := make([]api.CIDRRule, 0, len(egress.ToCIDRSet))
	for _, delCIDRRule := range delCIDRRules {
		delSlice = append(delSlice, *delCIDRRule)
	}
	toReleasePrefixes = policy.GetPrefixesFromCIDRSet(delSlice)

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

// PreprocessRules translates egress rules that apply to external services (ToServices)
func PreprocessRules(r api.Rules, cache *ServiceCache) error {

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	for _, rule := range r {
		// Translate only handles egress rules
		if rule.Egress == nil {
			continue
		}
		for ns, ep := range cache.endpoints {
			svc, ok := cache.services[ns]
			// Normally, only services without a label selector (i.e. empty services)
			// are allowed as targets of a toServices rule.
			// This is to minimize the chances of a pod IP being selected by this rule, which might
			// cause conflicting entries in the ipcache.
			//
			// This requirement, however, is dropped for HighScale IPCache mode, because pod IPs are
			// normally excluded from the ipcache regardless.
			if ok && (option.Config.EnableHighScaleIPcache || svc.IsExternal()) {
				eps := ep.GetEndpoints()
				if eps != nil {
					t := NewK8sTranslator(ns, Endpoints{}, *eps, svc.Labels)
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
	serviceInfo ServiceID,
	oldEPs, newEPs Endpoints,
	labels map[string]string,
) RuleTranslator {
	return RuleTranslator{
		Service:       serviceInfo,
		OldEndpoint:   oldEPs,
		NewEndpoint:   newEPs,
		ServiceLabels: labels,
	}
}
