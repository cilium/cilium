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

// +build !privileged_tests

package fqdn

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/dns"
)

var (
	// cilium.io dns target, no rule name => no rule labels
	rule1 = makeRule("", "cilium.io")

	// cilium.io dns target, no rule name => no rule labels
	rule2 = makeRule("", "cilium.io")

	// cilium.io, github.com dns targets
	rule3 = makeRule("rule3", "cilium.io", "github.com")

	// github.com dns target
	rule4 = makeRule("rule4", "github.com")

	ipLookups = map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"): {
			TTL: 60,
			IPs: []net.IP{
				net.ParseIP("172.217.18.174"),
				net.ParseIP("2a00:1450:4001:811::200e")}},
		dns.Fqdn("github.com"): {
			TTL: 60,
			IPs: []net.IP{
				net.ParseIP("98.138.219.231"),
				net.ParseIP("72.30.35.10"),
				net.ParseIP("001:4998:c:1023::4"),
				net.ParseIP("001:4998:58:1836::10")}},
	}
)

func makeRule(key string, dnsNames ...string) *api.Rule {
	matchNames := []string{}
	for _, name := range dnsNames {
		matchNames = append(matchNames,
			fmt.Sprintf(`{"matchName": "%s"}`, dns.Fqdn(name)))
	}

	rule := `{`
	if key != "" {
		rule += fmt.Sprintf(`"labels": [{ "key": "%s" }],`, key)
	}
	rule += fmt.Sprintf(`"endpointSelector": {
    "matchLabels": {
      "class": "xwing"
    }
  },
  "egress": [
    {
      "toFQDNs": [
      %s
      ]
    }
  ]
}`, strings.Join(matchNames, ",\n"))
	//fmt.Print(rule)
	return mustParseRule(rule)
}

func parseRule(rule string) (parsedRule *api.Rule, err error) {
	if err := json.Unmarshal([]byte(rule), &parsedRule); err != nil {
		return nil, err
	}

	if err := parsedRule.Sanitize(); err != nil {
		return nil, err
	}

	return parsedRule, nil
}

func mustParseRule(rule string) (parsedRule *api.Rule) {
	parsedRule, err := parseRule(rule)
	if err != nil {
		panic(fmt.Sprintf("Error parsing FQDN test rules: %s", err))
	}
	return parsedRule
}

// LookupDNSNames is a wrappable dummy used by the tests. It counts the number
// of times a name is looked up in lookups, and uses ipData as a source for the
// "response"
func lookupDNSNames(ipData map[string]*DNSIPRecords, lookups map[string]int, dnsNames []string) (DNSIPs map[string]*DNSIPRecords) {
	DNSIPs = make(map[string]*DNSIPRecords)
	for _, dnsName := range dnsNames {
		lookups[dnsName] += 1
		DNSIPs[dnsName] = ipData[dnsName]
	}
	return DNSIPs
}
