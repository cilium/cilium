// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import "github.com/cilium/cilium/pkg/policy"

type nullAuthHandler struct {
}

func (r *nullAuthHandler) authenticate() error {
	// Authentication trivially done
	return nil
}

func (r *nullAuthHandler) authType() policy.AuthType {
	return policy.AuthTypeNull
}
