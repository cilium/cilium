// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testcertificatemanager

import (
	"context"

	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	fakeCA         = "fake ca"
	fakePublicKey  = "fake public key"
	fakePrivateKey = "fake private key"
)

func (_ *Fake) GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext, ns string) (ca, public, private string, inlineSecrets bool, err error) {
	name := tlsCtx.Secret.Name
	public = fakePublicKey + " " + name
	private = fakePrivateKey + " " + name
	ca = fakeCA + " " + name

	inlineSecrets = true
	return
}

type Fake struct{}
