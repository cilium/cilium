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

package k8s

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/apimachinery/pkg/labels"
)

var _ policy.Translator = RuleTranslator{}

// RuleTranslator implements pkg/policy.Translator interface
// Translate populates/depopulates given rule with ToCIDR rules
// Based on provided service/endpoint
type RuleTranslator struct {
	Service       ServiceID
	Endpoint      Endpoints
	ServiceLabels map[string]string
	Revert        bool
	IPCache       ipcache.Implementation
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
			if err := generateToCidrFromEndpoint(r, k.Endpoint, k.IPCache); err != nil {
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
			if err := deleteToCidrFromEndpoint(r, k.Endpoint, k.IPCache); err != nil {
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
	impl ipcache.Implementation) error {

	// Non-nil implementation here implies that this translation is
	// occurring after policy import. This means that the CIDRs were not
	// known at that time, so the IPCache hasn't been informed about them.
	// In this case, it's the job of this Translator to notify the IPCache.
	if impl != nil {
		prefixes, err := endpoint.CIDRPrefixes()
		if err != nil {
			return err
		}
		if _, err := ipcache.AllocateCIDRs(impl, prefixes); err != nil {
			return err
		}
	}

	// This will generate one-address CIDRs consisting of endpoint backend ip
	mask := net.CIDRMask(128, 128)
	for ip := range endpoint.Backends {
		epIP := net.ParseIP(ip)
		if epIP == nil {
			return fmt.Errorf("Unable to parse ip: %s", ip)
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
	impl ipcache.Implementation) error {

	newToCIDR := make([]api.CIDRRule, 0, len(egress.ToCIDRSet))
	deleted := make([]api.CIDRRule, 0, len(egress.ToCIDRSet))

	for ip := range endpoint.Backends {
		epIP := net.ParseIP(ip)
		if epIP == nil {
			return fmt.Errorf("Unable to parse ip: %s", ip)
		}

		for _, c := range egress.ToCIDRSet {
			_, cidr, err := net.ParseCIDR(string(c.Cidr))
			if err != nil {
				return err
			}
			// if endpoint is not in CIDR or it's not
			// generated it's ok to retain it
			if !cidr.Contains(epIP) || !c.Generated {
				newToCIDR = append(newToCIDR, c)
			} else {
				deleted = append(deleted, c)
			}
		}
	}

	egress.ToCIDRSet = newToCIDR
	if impl != nil {
		prefixes := policy.GetPrefixesFromCIDRSet(deleted)
		ipcache.ReleaseCIDRs(prefixes)
	}

	return nil
}

// PreprocessRules translates rules that apply to headless services
func PreprocessRules(r api.Rules, cache *ServiceCache) error {

	// Headless services are translated prior to policy import, so the
	// policy will contain all of the CIDRs and can handle ipcache
	// interactions when the policy is imported. Ignore the IPCache
	// interaction here and just set the implementation to nil.
	ipcache := ipcache.Implementation(nil)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	for _, rule := range r {
		for ns, ep := range cache.endpoints {
			svc, ok := cache.services[ns]
			if ok && svc.IsExternal() {
				t := NewK8sTranslator(ns, *ep, false, svc.Labels, ipcache)
				err := t.Translate(rule, &policy.TranslationResult{})
				if err != nil {
					return err
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
	ipcache ipcache.Implementation) RuleTranslator {

	return RuleTranslator{serviceInfo, endpoint, labels, revert, ipcache}
}
