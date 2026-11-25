// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestGetStatusStaleKubernetesProbe(t *testing.T) {
	logger := hivetest.Logger(t)
	_, cs := k8sClient.NewFakeClientset(logger)

	cfg := Config{
		StatusCollectorInterval:          5 * time.Millisecond,
		StatusCollectorWarningThreshold:  15 * time.Millisecond,
		StatusCollectorFailureThreshold:  40 * time.Millisecond,
		StatusCollectorProbeCheckTimeout: 3 * time.Second,
	}

	sc := &statusCollector{
		statusCollector: newCollector(logger, cfg),
		statusParams: statusParams{
			Clientset: cs,
		},
	}

	var blockK8s, blockIPAM atomic.Bool
	unblockK8s := make(chan struct{})
	unblockIPAM := make(chan struct{})

	probes := []Probe{
		{
			Name: k8sProbeName,
			Probe: func(ctx context.Context) (any, error) {
				if blockK8s.Load() {
					<-unblockK8s
				}
				return &models.K8sStatus{State: models.StatusStateOk, Msg: "ok"}, nil
			},
			OnStatusUpdate: func(status Status) {
				sc.statusCollectMutex.Lock()
				defer sc.statusCollectMutex.Unlock()

				if status.Err != nil {
					sc.statusResponse.Kubernetes = &models.K8sStatus{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}
				if s, ok := status.Data.(*models.K8sStatus); ok {
					sc.statusResponse.Kubernetes = s
				}
			},
		},
		{
			Name: "ipam",
			Probe: func(ctx context.Context) (any, error) {
				if blockIPAM.Load() {
					<-unblockIPAM
				}
				return &models.IPAMStatus{Status: "ok"}, nil
			},
			OnStatusUpdate: func(status Status) {
				sc.statusCollectMutex.Lock()
				defer sc.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.IPAMStatus); ok {
						sc.statusResponse.Ipam = s
					}
				}
			},
		},
	}

	sc.statusCollector.StartProbes(probes)
	t.Cleanup(func() {
		select {
		case <-unblockK8s:
		default:
			close(unblockK8s)
		}
		select {
		case <-unblockIPAM:
		default:
			close(unblockIPAM)
		}
		sc.statusCollector.Close()
	})

	require.NoError(t, sc.statusCollector.WaitForFirstRun(t.Context()))
	sc.statusCollectMutex.Lock()
	sc.allProbesInitialized = true
	sc.statusCollectMutex.Unlock()

	// Baseline: both probes healthy.
	sr := sc.GetStatus(true, true)
	require.Equal(t, models.StatusStateOk, sr.Cilium.State)
	require.Empty(t, sr.Stale)

	// Stall only the kubernetes probe beyond FailureThreshold.
	blockK8s.Store(true)
	require.NoError(t, testutils.WaitUntil(func() bool {
		_, stale := sc.statusCollector.GetStaleProbes()[k8sProbeName]
		return stale
	}, 2*time.Second))

	// When Kubernetes connectivity is not required, stale kubernetes probe must not fail status.
	srBriefNoK8s := sc.GetStatus(true, false)
	require.Equal(t, models.StatusStateOk, srBriefNoK8s.Cilium.State)
	require.Empty(t, srBriefNoK8s.Stale)

	// Full status with requireK8sConnectivity=false also stays Ok while preserving Kubernetes failure details.
	srFullNoK8s := sc.GetStatus(false, false)
	require.Equal(t, models.StatusStateOk, srFullNoK8s.Cilium.State)
	require.Empty(t, srFullNoK8s.Stale)
	require.NotNil(t, srFullNoK8s.Kubernetes)
	require.Equal(t, models.StatusStateFailure, srFullNoK8s.Kubernetes.State)

	// When Kubernetes connectivity is required, stale kubernetes probe still triggers Warning.
	for _, brief := range []bool{true, false} {
		srReqK8s := sc.GetStatus(brief, true)
		require.Equal(t, models.StatusStateWarning, srReqK8s.Cilium.State)
		require.Contains(t, srReqK8s.Cilium.Msg, "Stale status data")
		require.Contains(t, srReqK8s.Stale, k8sProbeName)
	}

	// If another local probe is also stale, requireK8sConnectivity=false must still report Warning.
	blockIPAM.Store(true)
	require.NoError(t, testutils.WaitUntil(func() bool {
		_, stale := sc.statusCollector.GetStaleProbes()["ipam"]
		return stale
	}, 2*time.Second))

	srBothStaleNoK8s := sc.GetStatus(true, false)
	require.Equal(t, models.StatusStateWarning, srBothStaleNoK8s.Cilium.State)
	require.Contains(t, srBothStaleNoK8s.Cilium.Msg, "Stale status data")
	require.Contains(t, srBothStaleNoK8s.Stale, "ipam")
	require.NotContains(t, srBothStaleNoK8s.Stale, k8sProbeName)

	// Unblock both probes and verify full recovery.
	blockK8s.Store(false)
	blockIPAM.Store(false)
	close(unblockK8s)
	close(unblockIPAM)

	require.NoError(t, testutils.WaitUntil(func() bool {
		s := sc.GetStatus(true, true)
		return s.Cilium != nil && s.Cilium.State == models.StatusStateOk && len(s.Stale) == 0
	}, 2*time.Second))
}
