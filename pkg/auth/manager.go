// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import "github.com/cilium/cilium/pkg/monitor"

type AuthManager struct {
}

func NewAuthManager() *AuthManager {
	return &AuthManager{}
}

func (a *AuthManager) AuthRequired(dn *monitor.DropNotify, ci *monitor.ConnectionInfo) {
	log.Debugf("policy: Authentication required for identity %d->%d, %s %s:%d->%s:%d",
		dn.SrcLabel, dn.DstLabel, ci.Proto, ci.SrcIP, ci.SrcPort, ci.DstIP, ci.DstPort)
}
