// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

func TestEndpointLogFormat(t *testing.T) {
	setupEndpointSuite(t)

	// Default log format is text
	do := &DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil, nil)}
	ep := NewTestEndpointWithState(t, do, do, testipcache.NewMockIPCache(), nil, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)

	_, ok := ep.getLogger().Logger.Formatter.(*logrus.TextFormatter)
	require.Equal(t, true, ok)

	// Log format is JSON when configured
	logging.SetLogFormat(logging.LogFormatJSON)
	defer func() {
		logging.SetLogFormat(logging.LogFormatText)
	}()
	do = &DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil, nil)}
	ep = NewTestEndpointWithState(t, do, do, testipcache.NewMockIPCache(), nil, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)

	_, ok = ep.getLogger().Logger.Formatter.(*logrus.JSONFormatter)
	require.Equal(t, true, ok)
}

func TestPolicyLog(t *testing.T) {
	setupEndpointSuite(t)

	do := &DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil, nil)}
	ep := NewTestEndpointWithState(t, do, do, testipcache.NewMockIPCache(), nil, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)

	// Initially nil
	policyLogger := ep.getPolicyLogger()
	require.Nil(t, policyLogger)

	// Enable DebugPolicy option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionEnabled)
	require.Equal(t, true, ep.Options.IsEnabled(option.DebugPolicy))
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	require.NotNil(t, policyLogger)
	defer func() {
		// remote created log file when we are done.
		err := os.Remove(filepath.Join(option.Config.StateDir, "endpoint-policy.log"))
		require.Nil(t, err)
	}()

	// Test logging, policyLogger must not be nil
	policyLogger.Info("testing policy logging")

	// Test logging with integrated nil check, no fields
	ep.PolicyDebug(nil, "testing PolicyDebug")
	ep.PolicyDebug(logrus.Fields{"testField": "Test Value"}, "PolicyDebug with fields")

	// Disable option
	ep.Options.SetValidated(option.DebugPolicy, option.OptionDisabled)
	require.Equal(t, false, ep.Options.IsEnabled(option.DebugPolicy))
	ep.UpdateLogger(nil)
	policyLogger = ep.getPolicyLogger()
	require.Nil(t, policyLogger)

	// Verify file exists and contains the logged message
	buf, err := os.ReadFile(filepath.Join(option.Config.StateDir, "endpoint-policy.log"))
	require.Nil(t, err)
	require.Equal(t, true, bytes.Contains(buf, []byte("testing policy logging")))
	require.Equal(t, true, bytes.Contains(buf, []byte("testing PolicyDebug")))
	require.Equal(t, true, bytes.Contains(buf, []byte("Test Value")))
}
