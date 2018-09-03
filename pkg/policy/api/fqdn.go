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

package api

import "regexp"

type FQDNSelector struct {
	MatchName string `json:"matchName,omitempty"`
}

// sanitize for FQDNSelector is a little wonky. While we do more processing
// when using MatchName the basic requirement is that is a valid regexp. We
// test that it can compile here.
func (s *FQDNSelector) sanitize() error {
	// All L3 toFQDNs matchNames can be regexes (although we will treat some as
	// plain strings in the DNS Poller)
	_, err := regexp.Compile(s.MatchName)
	return err
}

// PortRuleDNS is a list of allowed DNS lookups.
type PortRuleDNS FQDNSelector

// Sanitize checks that the matchName in the portRule can be compiled as a
// regex. It does not check that a DNS name is a valid DNS name.
func (kr *PortRuleDNS) Sanitize() error {
	// All L7 toFQDNs matchNames are regexes
	_, err := regexp.Compile(kr.MatchName)
	if err != nil {
		return err
	}
	return nil
}
