// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
)

type operatorHandle struct {
	t    *testing.T
	hive *hive.Hive
}

func (h *operatorHandle) tearDown() {
	if err := h.hive.Stop(context.Background()); err != nil {
		h.t.Fatalf("Operator hive failed to stop: %s", err)
	}
}
