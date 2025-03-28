// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rules

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

type DNSRulesService interface {
	// GetDNSRules creates a fresh copy of DNS rules that can be used when
	// endpoint is restored on a restart.
	// The endpoint lock must not be held while calling this function.
	GetDNSRules(epID uint16) restore.DNSRules

	// RemoveRestoredDNSRules removes any restored DNS rules for
	// this endpoint from the DNS proxy.
	RemoveRestoredDNSRules(epID uint16)
}

type dnsRulesService struct {
	logger     *slog.Logger
	dnsProxy   defaultdns.Proxy
	policyRepo policy.PolicyRepository
}

var _ DNSRulesService = &dnsRulesService{}

func NewDNSRulesService(logger *slog.Logger, dnsProxy defaultdns.Proxy, policyRepo policy.PolicyRepository) DNSRulesService {
	return &dnsRulesService{
		logger:     logger,
		dnsProxy:   dnsProxy,
		policyRepo: policyRepo,
	}
}

func (r *dnsRulesService) GetDNSRules(epID uint16) restore.DNSRules {
	dnsProxy := r.dnsProxy.Get()
	if dnsProxy == nil {
		return nil
	}

	// We get the latest consistent view on the DNS rules by getting handle to the latest
	// coherent state of the selector cache
	version := r.policyRepo.GetSelectorCache().GetVersionHandle()
	rules, err := dnsProxy.GetRules(version, epID)
	version.Close()

	if err != nil {
		r.logger.Error("Could not get DNS Rules",
			logfields.Error, err,
			logfields.EndpointID, epID,
		)
		return nil
	}
	return rules
}

func (r *dnsRulesService) RemoveRestoredDNSRules(epID uint16) {
	dnsProxy := r.dnsProxy.Get()
	if dnsProxy == nil {
		return
	}

	dnsProxy.RemoveRestoredRules(epID)
}
