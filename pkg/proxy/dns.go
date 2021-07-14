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

package proxy

import (
	"context"
	"regexp"

	fqdnpb "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/sirupsen/logrus"
)

var (
	// DefaultDNSProxy is the global, shared, DNS Proxy singleton.
	DefaultDNSProxy     *dnsproxy.DNSProxy
	FQDNProxyGRPCClient fqdnpb.FQDNProxyClient
)

// dnsRedirect implements the Redirect interface for an l7 proxy
type dnsRedirect struct {
	redirect             *Redirect
	endpointInfoRegistry logger.EndpointInfoRegistry
	conf                 dnsConfiguration
	currentRules         policy.L7DataMap
}

type dnsConfiguration struct {
}

// setRules replaces old l7 rules of a redirect with new ones.
// TODO: Get rid of the duplication between 'currentRules' and 'r.rules'
func (dr *dnsRedirect) setRules(wg *completion.WaitGroup, newRules policy.L7DataMap) error {
	log.WithFields(logrus.Fields{
		"newRules":           newRules,
		logfields.EndpointID: dr.redirect.endpointID,
	}).Debug("DNS Proxy updating matchNames in allowed list during UpdateRules")
	//if err := DefaultDNSProxy.UpdateAllowed(dr.redirect.endpointID, dr.redirect.dstPort, newRules); err != nil {
	//	return err
	//}

	msg := &fqdnpb.FQDNRules{
		EndpointID: dr.redirect.endpointID,
		DestPort:   uint32(dr.redirect.dstPort),
	}
	unifiedRules, err := dnsproxy.GetSelectorRegexMap(newRules)
	if err != nil {
		log.WithFields(logrus.Fields{
			"newRules":           newRules,
			logfields.EndpointID: dr.redirect.endpointID,
		}).WithError(err).Error("Couldn't convert new rules to Selector->Regex map")
	}
	msg.Rules = &fqdnpb.L7Rules{
		SelectorRegexMapping:      make(map[string]string),
		SelectorIdentitiesMapping: make(map[string]*fqdnpb.IdentityList),
	}

	for selector, regex := range unifiedRules {
		msg.Rules.SelectorRegexMapping[selector.String()] = regex.String()

		nids := selector.GetSelections()
		ids := make([]uint32, len(nids))
		for i, nid := range nids {
			ids[i] = uint32(nid)
		}
		msg.Rules.SelectorIdentitiesMapping[selector.String()] = &fqdnpb.IdentityList{
			List: ids,
		}
	}

	if _, err := FQDNProxyGRPCClient.UpdateAllowed(context.TODO(), msg); err != nil {
		log.WithFields(logrus.Fields{
			"newRules":           newRules,
			logfields.EndpointID: dr.redirect.endpointID,
		}).WithError(err).Error("Failed to UpdateAllowed")
	}

	//TODO: don't repeat this code in daemon.GetRules, move out to a separate package
	//possibly with reverse direction conversion factored out from fqdn proxy
	rules, err := FQDNProxyGRPCClient.GetRules(context.TODO(), &fqdnpb.EndpointID{EndpointID: uint32(dr.redirect.endpointID)})
	if err != nil {
		log.WithField(logfields.EndpointID, dr.redirect.endpointID).WithError(err).Error("Failed to retrieve DNS rules from proxy")
		return nil
	}

	result := restore.DNSRules{}

	for port, msgIpRules := range rules.Rules {
		ipRules := make(restore.IPRules, 0, len(msgIpRules.List))

		for _, msgIpRule := range msgIpRules.List {
			ipRule := restore.IPRule{
				Re: restore.RuleRegex{
					Regexp: regexp.MustCompile(msgIpRule.Regex),
				},
				IPs: make(map[string]struct{}, len(msgIpRule.Ips)),
			}

			for _, ip := range msgIpRule.Ips {
				ipRule.IPs[ip] = struct{}{}
			}

			ipRules = append(ipRules, ipRule)
		}

		result[uint16(port)] = ipRules
	}

	dr.redirect.localEndpoint.OnDNSPolicyUpdateLocked(result)
	dr.currentRules = copyRules(dr.redirect.rules)

	return nil
}

// UpdateRules atomically replaces the proxy rules in effect for this redirect.
// It is not aware of revision number and doesn't account for out-of-order
// calls to UpdateRules or the returned RevertFunc.
func (dr *dnsRedirect) UpdateRules(wg *completion.WaitGroup) (revert.RevertFunc, error) {
	oldRules := dr.currentRules
	err := dr.setRules(wg, dr.redirect.rules)
	revertFunc := func() error {
		return dr.setRules(nil, oldRules)
	}
	return revertFunc, err
}

// Close the redirect.
func (dr *dnsRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	return func() {
		//TODO: move this out of the function to decrease memory consumption?
		msg := &fqdnpb.FQDNRules{
			EndpointID: dr.redirect.endpointID,
			DestPort:   uint32(dr.redirect.dstPort),
			Rules:      &fqdnpb.L7Rules{},
		}
		if _, err := FQDNProxyGRPCClient.UpdateAllowed(context.TODO(), msg); err != nil {
			log.WithFields(logrus.Fields{
				logfields.EndpointID: dr.redirect.endpointID,
			}).WithError(err).Error("Failed to UpdateAllowed with on redirect close")
		}
		//DefaultDNSProxy.UpdateAllowed(dr.redirect.endpointID, dr.redirect.dstPort, nil)
		dr.redirect.localEndpoint.OnDNSPolicyUpdateLocked(nil)
		dr.currentRules = nil
	}, nil
}

// creatednsRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createDNSRedirect(r *Redirect, conf dnsConfiguration, endpointInfoRegistry logger.EndpointInfoRegistry) (RedirectImplementation, error) {
	dr := &dnsRedirect{
		redirect:             r,
		conf:                 conf,
		endpointInfoRegistry: endpointInfoRegistry,
	}

	log.WithFields(logrus.Fields{
		"dnsRedirect": dr,
		"conf":        conf,
	}).Debug("Creating DNS Proxy redirect")

	return dr, dr.setRules(nil, r.rules)
}

func copyRules(rules policy.L7DataMap) policy.L7DataMap {
	currentRules := policy.L7DataMap{}
	for key, val := range rules {
		currentRules[key] = val
	}
	return currentRules
}
