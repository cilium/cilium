// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func Test_wrapper(t *testing.T) {
	h := New()
	require.NotNil(t, h)

	tlog := hivetest.Logger(t)
	err := h.Start(tlog, context.TODO())
	require.NoError(t, err)

	err = h.Stop(tlog, context.TODO())
	require.NoError(t, err)
}
