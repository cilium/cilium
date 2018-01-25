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

	"k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

var _ policy.Translator = RuleTranslator{}

// RuleTranslator implements pkg/policy.Translator interface
// Translate populates/depopulates given rule with ToCIDR rules
// Based on provided service/endpoint
type RuleTranslator struct {
	Service       types.K8sServiceNamespace
	Endpoint      types.K8sServiceEndpoint
	ServiceLabels map[string]string
	Revert        bool
}

// Translate calls TranslateEgress on all r.Egress rules
func (k RuleTranslator) Translate(r *api.Rule) error {
	for egressIndex := range r.Egress {
		err := k.TranslateEgress(&r.Egress[egressIndex])
		if err != nil {
			return err
		}
	}
	return nil
}

// TranslateEgress populates/depopulates egress rules with ToCIDR entries based
// on toService entries
func (k RuleTranslator) TranslateEgress(r *api.EgressRule) error {
	err := k.depopulateEgress(r)
	if err != nil {
		return err
	}
	if !k.Revert {
		err := k.populateEgress(r)
		if err != nil {
			return err
		}
	}
	return nil
}

func (k RuleTranslator) populateEgress(r *api.EgressRule) error {
	for _, service := range r.ToServices {
		es := api.EndpointSelector(service.K8sServiceSelector)
		if service.K8sService == api.K8sServiceNamespace(k.Service) ||
			es.Matches(labels.Set(k.ServiceLabels)) {

			if err := generateToCidrFromEndpoint(r, k.Endpoint); err != nil {
				return err
			}
			// TODO: generateToPortsFromEndpoint when ToPorts and ToCIDR are compatible
		}
	}
	return nil
}

func (k RuleTranslator) depopulateEgress(r *api.EgressRule) error {
	for _, service := range r.ToServices {
		es := api.EndpointSelector(service.K8sServiceSelector)
		if service.K8sService == api.K8sServiceNamespace(k.Service) ||
			es.Matches(labels.Set(k.ServiceLabels)) {

			if err := deleteToCidrFromEndpoint(r, k.Endpoint); err != nil {
				return err
			}
			// TODO: generateToPortsFromEndpoint when ToPorts and ToCIDR are compatible
		}
	}
	return nil
}

// generateToCidrFromEndpoint takes an egress rule and populates it with
// ToCIDR rules based on provided endpoint object
func generateToCidrFromEndpoint(
	egress *api.EgressRule, endpoint types.K8sServiceEndpoint) error {

	// This will generate one-address CIDRs consisting of endpoint backend ip
	mask := net.CIDRMask(128, 128)
	for ip := range endpoint.BEIPs {
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

// deleteToCidrFromEndpoint takes an egress rule and removes
// ToCIDR rules matching endpoint
func deleteToCidrFromEndpoint(
	egress *api.EgressRule, endpoint types.K8sServiceEndpoint) error {

	newToCIDR := make([]api.CIDRRule, 0, len(egress.ToCIDRSet))

	for ip := range endpoint.BEIPs {
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
			}
		}
	}

	egress.ToCIDRSet = newToCIDR

	return nil
}

// PreprocessRules translates rules that apply to headless services
func PreprocessRules(
	r api.Rules,
	endpoints map[types.K8sServiceNamespace]*types.K8sServiceEndpoint,
	services map[types.K8sServiceNamespace]*types.K8sServiceInfo) error {

	for _, rule := range r {
		for ns, ep := range endpoints {
			svc, ok := services[ns]
			if ok && svc.IsHeadless {
				t := NewK8sTranslator(ns, *ep, false, svc.Labels)
				err := t.Translate(rule)
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
	serviceInfo types.K8sServiceNamespace,
	endpoint types.K8sServiceEndpoint,
	revert bool,
	labels map[string]string) RuleTranslator {

	return RuleTranslator{serviceInfo, endpoint, labels, revert}
}
