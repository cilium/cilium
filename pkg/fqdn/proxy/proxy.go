// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package proxy

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
)

type DNSProxier interface {
	GetRules(uint16) (restore.DNSRules, error)
	RemoveRestoredRules(uint16)
	UpdateAllowed(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error
	GetBindPort() uint16
	SetRejectReply(string)
	RestoreRules(op *endpoint.Endpoint)
}
