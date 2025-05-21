// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

func TestPolicyLog(t *testing.T) {
	setupEndpointSuite(t)
	logger := hivetest.Logger(t)

	do := &DummyOwner{repo: policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())}

	model := newTestEndpointModel(12345, StateReady)
	ep, err := NewEndpointFromChangeModel(t.Context(), nil, &MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, do.repo, testipcache.NewMockIPCache(), nil, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

	// Initially nil
	policyLogger := ep.getPolicyLogger()
	require.Nil(t, policyLogger)

	// Enable DebugPolicy option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionEnabled)
	require.True(t, ep.Options.IsEnabled(option.DebugPolicy))
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	require.NotNil(t, policyLogger)
	defer func() {
		// remote created log file when we are done.
		err := os.Remove(filepath.Join(option.Config.StateDir, "endpoint-policy.log"))
		require.NoError(t, err)
	}()

	// Test logging, policyLogger must not be nil
	policyLogger.Info("testing policy logging")

	// Test logging with integrated nil check, no fields
	ep.PolicyDebug("testing PolicyDebug")
	ep.PolicyDebug("PolicyDebug with fields", slog.String("testField", "Test Value"))

	// Disable option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionDisabled)
	require.False(t, ep.Options.IsEnabled(option.DebugPolicy))
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	require.Nil(t, policyLogger)

	// Verify file exists and contains the logged message
	buf, err := os.ReadFile(filepath.Join(option.Config.StateDir, "endpoint-policy.log"))
	require.NoError(t, err)
	require.True(t, bytes.Contains(buf, []byte("testing policy logging")))
	require.True(t, bytes.Contains(buf, []byte("testing PolicyDebug")))
	require.True(t, bytes.Contains(buf, []byte("Test Value")))
}
