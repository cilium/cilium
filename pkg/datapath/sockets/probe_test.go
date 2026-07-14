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
	p := newSocketInetProbe()
	assert.NoError(t, p.InetDiagDestroyTCPEnabled(hivetest.Logger(t)))
	assert.NoError(t, p.InetDiagDestroyUDPEnabled(hivetest.Logger(t)))
}
