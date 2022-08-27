// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
)

type operatorHandle struct {
	cancel context.CancelFunc
}

func (h *operatorHandle) tearDown() {
	h.cancel()
}
