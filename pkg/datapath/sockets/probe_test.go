// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"errors"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"

	"github.com/cilium/hive/hivetest"

	"github.com/stretchr/testify/assert"
)

func TestSockDestroyProbeHandleSocketError(t *testing.T) {
	wantErr := errors.New("netlink receive error")
	probe := sockDestroyProbe{logger: hivetest.Logger(t)}

	// Netlink receive errors do not include a socket. The callback must return
	// the error before dereferencing it.
	gotErr := probe.handleSocket(nil, wantErr)
	assert.ErrorIs(t, gotErr, wantErr)
}

func TestPrivilegedProbetInetDiagDestroyEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)
	assert.NoError(t, InetDiagDestroyEnabled(hivetest.Logger(t), true, true))
	assert.NoError(t, InetDiagDestroyEnabled(hivetest.Logger(t), false, false))
}
