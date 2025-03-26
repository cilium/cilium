// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package regeneration

import (
	"context"

	"github.com/cilium/cilium/pkg/fqdn/restore"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {
	// QueueEndpointBuild puts the given endpoint in the processing queue
	QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error)

	// SendNotification is called to emit an agent notification
	SendNotification(msg monitorAPI.AgentNotifyMessage) error

	// GetDNSRules creates a fresh copy of DNS rules that can be used when
	// endpoint is restored on a restart.
	// The endpoint lock must not be held while calling this function.
	GetDNSRules(epID uint16) restore.DNSRules

	// RemoveRestoredDNSRules removes any restored DNS rules for
	// this endpoint from the DNS proxy.
	RemoveRestoredDNSRules(epID uint16)
}
