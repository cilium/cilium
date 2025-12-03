// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

type DNSProxier interface {
	GetRules(uint16) (restore.DNSRules, error)
	RemoveRestoredRules(uint16)
	UpdateAllowed(endpointID uint64, destPort restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error)
	GetBindPort() uint16
	RestoreRules(op *endpoint.Endpoint)
	Cleanup()

	Listen(port uint16) error
}
