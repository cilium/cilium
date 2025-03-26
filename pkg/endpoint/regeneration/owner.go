// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package regeneration

import (
	"github.com/cilium/cilium/pkg/fqdn/restore"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {
	// GetDNSRules creates a fresh copy of DNS rules that can be used when
	// endpoint is restored on a restart.
	// The endpoint lock must not be held while calling this function.
	GetDNSRules(epID uint16) restore.DNSRules

	// RemoveRestoredDNSRules removes any restored DNS rules for
	// this endpoint from the DNS proxy.
	RemoveRestoredDNSRules(epID uint16)
}
