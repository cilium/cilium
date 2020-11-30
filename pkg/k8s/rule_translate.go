// Copyright 2016-2019 Authors of Cilium
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
			if err := generateToCidrFromEndpoint(r, k.Endpoint, k.AllocatePrefixes); err != nil {
				return err
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
			if err := deleteToCidrFromEndpoint(r, k.Endpoint, k.AllocatePrefixes); err != nil {
				return err
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
func generateToCidrFromEndpoint(
	egress *api.EgressRule,
	endpoint Endpoints,
	allocatePrefixes bool) error {

	// allocatePrefixes if true here implies that this translation is
	// occurring after policy import. This means that the CIDRs were not
	// known at that time, so the IPCache hasn't been informed about them.
	// In this case, it's the job of this Translator to notify the IPCache.
	if allocatePrefixes {
		prefixes, err := endpoint.CIDRPrefixes()
		if err != nil {
			return err
		}
		// TODO: Collect new identities to be upserted to the ipcache only after all
		// endpoints have been regenerated later. This would make sure that any CIDRs in the
		// policy would be first pushed to the endpoint policies and then to the ipcache to
		// avoid traffic mapping to an ID that the endpoint policy maps do not know about
		// yet.
		if _, err := ipcache.AllocateCIDRs(prefixes, nil); err != nil {
			return err
		}
	}

	// This will generate one-address CIDRs consisting of endpoint backend ip
	mask := net.CIDRMask(128, 128)
	for ip := range endpoint.Backends {
		epIP := net.ParseIP(ip)
		if epIP == nil {
			return fmt.Errorf("unable to parse ip: %s", ip)
		}

		found := false
		for _, c := range egress.ToCIDRSet {
			_, cidr, err := net.ParseCIDR(string(c.Cidr))
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
			egress.ToCIDRSet = append(egress.ToCIDRSet, api.CIDRRule{
				Cidr:      api.CIDR(cidr.String()),
				Generated: true,
			})
		}
	}
	return nil
}

// deleteToCidrFromEndpoint takes an egress rule and removes ToCIDR rules
// matching endpoint. Returns an error if any of the backends are malformed.
//
// If all backends are valid, attempts to remove any ipcache CIDR mappings (and
// CIDR Identities) from the kvstore for backends in 'endpoint' that are being
// removed from the policy. On failure to release such kvstore mappings, errors
// will be logged but this function will return nil to allow subsequent
// processing to proceed.
func deleteToCidrFromEndpoint(
	egress *api.EgressRule,
	endpoint Endpoints,
	releasePrefixes bool) error {

	delCIDRRules := make(map[int]*api.CIDRRule, len(egress.ToCIDRSet))

	for ip := range endpoint.Backends {
		epIP := net.ParseIP(ip)
		if epIP == nil {
			return fmt.Errorf("unable to parse ip: %s", ip)
		}

		for i, c := range egress.ToCIDRSet {
			if _, ok := delCIDRRules[i]; ok {
				// it's already going to be deleted so we can continue
				continue
			}
			_, cidr, err := net.ParseCIDR(string(c.Cidr))
			if err != nil {
				return err
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
		return nil
	}

	if releasePrefixes {
		delSlice := make([]api.CIDRRule, 0, len(egress.ToCIDRSet))
		for _, delCIDRRule := range delCIDRRules {
			delSlice = append(delSlice, *delCIDRRule)
		}
		prefixes := policy.GetPrefixesFromCIDRSet(delSlice)
		ipcache.ReleaseCIDRs(prefixes)
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

	return nil
}

// PreprocessRules translates rules that apply to headless services
func PreprocessRules(r api.Rules, cache *ServiceCache) error {

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	for _, rule := range r {
		for ns, ep := range cache.endpoints {
			svc, ok := cache.services[ns]
			if ok && svc.IsExternal() {
				eps := ep.GetEndpoints()
				if eps != nil {
					t := NewK8sTranslator(ns, *eps, false, svc.Labels, false)
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

// NewK8sTranslator returns RuleTranslator
func NewK8sTranslator(
	serviceInfo ServiceID,
	endpoint Endpoints,
	revert bool,
	labels map[string]string,
	allocatePrefixes bool) RuleTranslator {

	return RuleTranslator{serviceInfo, endpoint, labels, revert, allocatePrefixes}
}
