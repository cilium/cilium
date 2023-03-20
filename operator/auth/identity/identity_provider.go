// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import "context"

// Provider is the interface that manages the identity operations.
type Provider interface {
	Upsert(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}
