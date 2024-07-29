// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package regeneration

import (
	"context"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {
	// QueueEndpointBuild puts the given endpoint in the processing queue
	QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error)

	// GetCompilationLock returns the mutex responsible for synchronizing compilation
	// of BPF programs.
	GetCompilationLock() datapath.CompilationLock

	// SendNotification is called to emit an agent notification
	SendNotification(msg monitorAPI.AgentNotifyMessage) error

	// Datapath returns a reference to the datapath implementation.
	Datapath() datapath.Datapath

	// GetDNSRules creates a fresh copy of DNS rules that can be used when
	// endpoint is restored on a restart.
	// The endpoint lock must not be held while calling this function.
	GetDNSRules(epID uint16) restore.DNSRules

	// RemoveRestoredDNSRules removes any restored DNS rules for
	// this endpoint from the DNS proxy.
	RemoveRestoredDNSRules(epID uint16)

	AddIdentity(*identity.Identity)
	RemoveIdentity(*identity.Identity)
	RemoveOldAddNewIdentity(*identity.Identity, *identity.Identity)
}
