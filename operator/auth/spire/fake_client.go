// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"context"

	"github.com/cilium/cilium/operator/auth/identity"
)

// NewFakeClient creates a new fake SPIRE client.
func NewFakeClient() identity.Provider {
	return fakeClient{
		ids: map[string]struct{}{},
	}
}

type fakeClient struct {
	ids map[string]struct{}
}

func (n fakeClient) Upsert(_ context.Context, id string) error {
	n.ids[id] = struct{}{}
	return nil
}

func (n fakeClient) Delete(_ context.Context, id string) error {
	delete(n.ids, id)
	return nil
}

func (n fakeClient) List(_ context.Context) ([]string, error) {
	ids := make([]string, 0, len(n.ids))
	for id := range n.ids {
		ids = append(ids, id)
	}
	return ids, nil
}
