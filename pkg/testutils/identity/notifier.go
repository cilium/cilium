// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testidentity

import "github.com/cilium/cilium/pkg/policy/api"

type DummyIdentityNotifier struct {
	Registered map[api.FQDNSelector]struct{}
}

func NewDummyIdentityNotifier() *DummyIdentityNotifier {
	return &DummyIdentityNotifier{
		Registered: make(map[api.FQDNSelector]struct{}),
	}
}

func (d DummyIdentityNotifier) RegisterFQDNSelector(selector api.FQDNSelector) {}

func (d DummyIdentityNotifier) UnregisterFQDNSelector(selector api.FQDNSelector) {}
