// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
)

func TestHint(t *testing.T) {
	var err error
	require.NoError(t, Hint(err))

	err = errors.New("foo bar")
	require.ErrorContains(t, Hint(err), "foo bar")

	err = fmt.Errorf("ayy lmao")
	require.ErrorContains(t, Hint(err), "ayy lmao")

	err = context.DeadlineExceeded
	require.ErrorContains(t, Hint(err), "Cilium API client timeout exceeded")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	err = ctx.Err()

	require.ErrorContains(t, Hint(err), "Cilium API client timeout exceeded")
}

func TestClusterReadiness(t *testing.T) {
	require.Equal(t, "ready", clusterReadiness(&models.RemoteCluster{Ready: true}))
	require.Equal(t, "not-ready", clusterReadiness(&models.RemoteCluster{Ready: false}))
}

func TestNumReadyClusters(t *testing.T) {
	require.Equal(t, 0, NumReadyClusters(nil))
	require.Equal(t, 2, NumReadyClusters([]*models.RemoteCluster{{Ready: true}, {Ready: true}, {Ready: false}}))
}

func TestFormStatusResponse(t *testing.T) {
	testCases := []struct {
		name     string
		sr       *models.StatusResponse
		sd       StatusDetails
		expected string
	}{
		{
			name:     "empty output",
			sr:       &models.StatusResponse{},
			sd:       StatusDetails{},
			expected: "NodeMonitor:\tDisabled\nProxy Status:\tNo managed proxy redirect\nGlobal Identity Range:\tUnknown\n",
		},
		{
			name: "IPv4",
			sr: &models.StatusResponse{
				KubeProxyReplacement: &models.KubeProxyReplacement{},
				Masquerading: &models.Masquerading{
					EnabledProtocols:    &models.MasqueradingEnabledProtocols{IPV4: true},
					Enabled:             true,
					SnatExclusionCidrV4: "10.0.0.0/16",
					Mode:                models.MasqueradingModeBPF,
				},
			},
			sd:       StatusDetails{},
			expected: "KubeProxyReplacement:\t\t\nNodeMonitor:\tDisabled\nMasquerading:\tBPF\t[]\t10.0.0.0/16  [IPv4: Enabled, IPv6: Disabled]\nProxy Status:\tNo managed proxy redirect\nGlobal Identity Range:\tUnknown\n",
		},
		{
			name: "IPv6",
			sr: &models.StatusResponse{
				KubeProxyReplacement: &models.KubeProxyReplacement{},
				Masquerading: &models.Masquerading{
					EnabledProtocols:    &models.MasqueradingEnabledProtocols{IPV6: true},
					Enabled:             true,
					SnatExclusionCidrV6: "fd00::/10",
					Mode:                models.MasqueradingModeBPF,
				},
			},
			sd:       StatusDetails{},
			expected: "KubeProxyReplacement:\t\t\nNodeMonitor:\tDisabled\nMasquerading:\tBPF\t[]\t fd00::/10 [IPv4: Disabled, IPv6: Enabled]\nProxy Status:\tNo managed proxy redirect\nGlobal Identity Range:\tUnknown\n",
		},
		{
			name: "IPv4 and IPv6",
			sr: &models.StatusResponse{
				KubeProxyReplacement: &models.KubeProxyReplacement{},
				Masquerading: &models.Masquerading{
					EnabledProtocols:    &models.MasqueradingEnabledProtocols{IPV4: true, IPV6: true},
					Enabled:             true,
					SnatExclusionCidrV6: "fd00::/10",
					SnatExclusionCidrV4: "10.0.0.0/16",
					Mode:                models.MasqueradingModeBPF,
				},
			},
			sd:       StatusDetails{},
			expected: "KubeProxyReplacement:\t\t\nNodeMonitor:\tDisabled\nMasquerading:\tBPF\t[]\t10.0.0.0/16 fd00::/10 [IPv4: Enabled, IPv6: Enabled]\nProxy Status:\tNo managed proxy redirect\nGlobal Identity Range:\tUnknown\n",
		},
	}
	for _, tc := range testCases {
		var b bytes.Buffer
		FormatStatusResponse(&b, tc.sr, tc.sd)
		assert.Contains(t, b.String(), tc.expected)
	}
}
