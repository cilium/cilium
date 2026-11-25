// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	versionapi "k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/k8s/client"
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

type discoveryOverrideClientset struct {
	client.Clientset
	discoveryClient discovery.DiscoveryInterfaces
}

func (c *discoveryOverrideClientset) Discovery() discovery.DiscoveryInterfaces {
	return c.discoveryClient
}

func resetK8sVersionCache(t *testing.T) {
	t.Helper()
	clear := func() {
		k8sVersionCache.lock.Lock()
		k8sVersionCache.version = ""
		k8sVersionCache.lastVersionCheck = time.Time{}
		k8sVersionCache.lock.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

func TestGetK8sStatusContextCancellationAndRecovery(t *testing.T) {
	resetK8sVersionCache(t)

	logger := hivetest.Logger(t)
	_, fakeCS := k8sClient.NewFakeClientset(logger)

	var block atomic.Bool
	block.Store(true)
	serverSawCancel := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		if block.Load() {
			<-r.Context().Done()
			select {
			case serverSawCancel <- struct{}{}:
			default:
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(versionapi.Info{
			Major:      "1",
			Minor:      "35",
			GitVersion: "v1.35.0",
			Platform:   "linux/amd64",
		})
	}))
	t.Cleanup(srv.Close)

	realK8s, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	require.NoError(t, err)

	sc := &statusCollector{
		statusParams: statusParams{
			Clientset: &discoveryOverrideClientset{
				Clientset:       fakeCS,
				discoveryClient: realK8s.Discovery(),
			},
		},
	}

	// Blocked /version request must be cancelled when the probe context expires.
	probeCtx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	st := sc.getK8sStatus(probeCtx)
	require.Equal(t, models.StatusStateFailure, st.State)
	require.Contains(t, st.Msg, context.DeadlineExceeded.Error())

	select {
	case <-serverSawCancel:
	case <-time.After(2 * time.Second):
		t.Fatal("expected blocked /version request to be cancelled on probe context timeout")
	}

	// Once the server unblocks, subsequent probes recover cleanly.
	block.Store(false)
	recovered := sc.getK8sStatus(t.Context())
	require.Equal(t, models.StatusStateOk, recovered.State)
	require.Equal(t, "1.35 (v1.35.0) [linux/amd64]", recovered.Msg)

	// Fake clientset Discovery().ServerVersionWithContext also works cleanly.
	resetK8sVersionCache(t)
	fakeSC := &statusCollector{
		statusParams: statusParams{
			Clientset: fakeCS,
		},
	}
	fakeSt := fakeSC.getK8sStatus(t.Context())
	require.Equal(t, models.StatusStateOk, fakeSt.State)
}
