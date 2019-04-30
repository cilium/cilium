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

package fqdn

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
)

// DNSPollerInterval is the time between 2 complete DNS lookup runs of the
// DNSPoller controller
// Note: This cannot be less than 1*time.Second, as it is used as a default
// for MinTTL in DNSPollerConfig
const DNSPollerInterval = 5 * time.Second

// StartDNSPoller spawns a singleton DNS polling controller. The controller
// will, periodically, run a DNS lookup for each ToFQDN target DNS name
// inserted with StartPollForDNSName.
// Note: Repeated calls will replace earlier instances of the controller.
func StartDNSPoller(poller *DNSPoller) {
	log.Debug("Starting DNS poller for ToFQDN rules")
	controller.NewManager().UpdateController("dns-poller", controller.ControllerParams{
		RunInterval: DNSPollerInterval,
		DoFunc:      poller.LookupUpdateDNS,
		StopFunc: func(ctx context.Context) error {
			log.Debug("Stopping DNS poller for ToFQDN rules")
			return nil
		},
	})
}

// DNSPoller periodically runs lookups for registered DNS names. It will emit
// regenerated policy rules when the IPs change. CNAMEs (and DNAMEs) are not
// handled directly, but will depend on the resolver's behavior.
// fqdn.Config can be opitonally used to set how the DNS lookups are
// executed (via LookupDNSNames) and how generated policy rules are handled
// (via AddGeneratedRulesAndUpdateSelectors).
type DNSPoller struct {
	lock.Mutex // this guards both maps and their contents

	// ruleManager is the backing RuleGen that tells this poller which names to
	// poll, and where to submit DNS updates.
	ruleManager *RuleGen

	// config is a copy from when this instance was initialized.
	// It is read-only once set
	config Config

	// DNSHistory is the collection of still-valid DNS responses intercepted
	// for the poller.
	// This is not protected by the mutex due to internally is using a mutex.
	DNSHistory *DNSCache
}

// NewDNSPoller creates an initialized DNSPoller. It does not start the controller (use .Start)
func NewDNSPoller(config Config, ruleManager *RuleGen) *DNSPoller {
	if config.MinTTL == 0 {
		config.MinTTL = 2 * int(DNSPollerInterval/time.Second)
	}

	if config.LookupDNSNames == nil {
		config.LookupDNSNames = DNSLookupDefaultResolver
	}

	if config.PollerResponseNotify == nil {
		config.PollerResponseNotify = noopPollerResponseNotify
	}

	return &DNSPoller{
		config:      config,
		ruleManager: ruleManager,
		DNSHistory:  NewDNSCacheWithLimit(config.MinTTL, config.OverLimit),
	}
}

// LookupUpdateDNS runs a DNS lookup for each stored DNS name, storing updates
// into ruleManager, which may emit regenerated policy rules.
// The general steps are:
// 1- take a snapshot of DNS names to lookup from .ruleManager, into dnsNamesToPoll
// 2- Do a DNS lookup for each DNS name (map key) in poller via LookupDNSNames
// 3- Update IPs for each dnsName in .ruleManager. If the IPs have changed for the
// name, it will generate and emit them.
func (poller *DNSPoller) LookupUpdateDNS(ctx context.Context) error {
	// Collect the DNS names that need lookups. This avoids locking
	// poller during lookups.
	dnsNamesToPoll := poller.ruleManager.GetDNSNames()

	// lookup the DNS names. Names with failures will not be updated (and we
	// will use the most recent data below)
	lookupTime := time.Now()
	updatedDNSIPs, errorDNSNames := poller.config.LookupDNSNames(dnsNamesToPoll)
	for dnsName, err := range errorDNSNames {
		log.WithError(err).WithField("matchName", dnsName).
			Warn("Cannot resolve FQDN. Traffic egressing to this destination may be incorrectly dropped due to stale data.")
	}
	for qname, response := range updatedDNSIPs {
		poller.DNSHistory.Update(lookupTime, qname, response.IPs, response.TTL)
		poller.config.PollerResponseNotify(lookupTime, qname, response)
	}

	return poller.ruleManager.UpdateGenerateDNS(lookupTime, updatedDNSIPs)
}

// noopPollerResponseNotify is used when no PollerResponseNotify is set.
func noopPollerResponseNotify(lookupTime time.Time, qname string, response *DNSIPRecords) {}
