// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
)

type Orchestrator interface {
	Reinitialize(ctx context.Context) error
}
