// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"

	"github.com/cilium/hive/hivetest"

	"github.com/stretchr/testify/assert"
)

func TestPrivilegedProbetInetDiagDestroyEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)
	assert.NoError(t, InetDiagDestroyEnabled(hivetest.Logger(t), true, true))
	assert.NoError(t, InetDiagDestroyEnabled(hivetest.Logger(t), false, false))
}
