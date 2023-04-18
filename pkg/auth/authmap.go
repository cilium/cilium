// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
)

// authMap provides an abstraction for the BPF map "auth"
type authMap interface {
	Update(key authKey, info authInfo) error
	Delete(key authKey) error
	Get(key authKey) (authInfo, error)
	All() (map[authKey]authInfo, error)
}

type authKey struct {
	localIdentity  identity.NumericIdentity
	remoteIdentity identity.NumericIdentity
	remoteNodeID   uint16
	authType       policy.AuthType
}

func (r authKey) String() string {
	return fmt.Sprintf("localIdentity=%d, remoteIdentity=%d, remoteNodeID=%d, authType=%d", r.localIdentity, r.remoteIdentity, r.remoteNodeID, r.authType)
}

type authInfo struct {
	expiration time.Time
}

func (r authInfo) String() string {
	return fmt.Sprintf("expiration=%s", r.expiration)
}
