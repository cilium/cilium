// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubblecell

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	"github.com/cilium/cilium/pkg/node"
)

type orderedCalls struct {
	mu    sync.Mutex
	calls []string
}

func (o *orderedCalls) add(call string) {
	o.mu.Lock()
	o.calls = append(o.calls, call)
	o.mu.Unlock()
}

func (o *orderedCalls) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.calls...)
}

type recordingNodeLabelsLifecycle struct {
	calls    *orderedCalls
	startErr error
	stops    int
}

func (l *recordingNodeLabelsLifecycle) Start() error {
	l.calls.add("start")
	return l.startErr
}

func (l *recordingNodeLabelsLifecycle) Stop() {
	l.calls.add("stop")
	l.stops++
}

type recordingMonitorAgent struct {
	monitorAgent.Agent
	calls *orderedCalls
}

func (a *recordingMonitorAgent) RegisterNewConsumer(consumer.MonitorConsumer) {
	a.calls.add("monitor")
}

func TestNodeLabelsDisabledHubbleDoesNotStartLifecycle(t *testing.T) {
	calls := &orderedCalls{}
	h := &hubbleIntegration{
		log:                   hivetest.Logger(t),
		directionalNodeLabels: &recordingNodeLabelsLifecycle{calls: calls},
		config:                config{EnableHubble: false},
	}

	require.NoError(t, h.Launch(context.Background()))
	require.Empty(t, calls.snapshot())
}

func TestNodeLabelsEnabledLaunchStartsBeforeObserverAndMonitor(t *testing.T) {
	calls := &orderedCalls{}
	lifecycle := &recordingNodeLabelsLifecycle{calls: calls}
	h := newNodeLabelsLaunchTestIntegration(t, lifecycle, calls,
		observeroption.WithOnServerInitFunc(func(observeroption.Server) error {
			calls.add("observer")
			return nil
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, h.Launch(ctx))
	require.Equal(t, []string{"start", "observer", "monitor"}, calls.snapshot())
	require.Zero(t, lifecycle.stops, "successful launch leaves cleanup to Hive OnStop")

	observer := h.observer.Load()
	require.NotNil(t, observer)
	close(observer.GetEventsChannel())
	<-observer.GetStopped()
	cancel()
}

func TestNodeLabelsLaunchStartErrorReturnsImmediately(t *testing.T) {
	calls := &orderedCalls{}
	startErr := errors.New("start failed")
	h := &hubbleIntegration{
		log: hivetest.Logger(t),
		directionalNodeLabels: &recordingNodeLabelsLifecycle{
			calls: calls, startErr: startErr,
		},
		config: config{EnableHubble: true},
	}

	require.ErrorIs(t, h.Launch(context.Background()), startErr)
	require.Equal(t, []string{"start"}, calls.snapshot())
}

func TestNodeLabelsLaterLaunchErrorStopsLifecycle(t *testing.T) {
	calls := &orderedCalls{}
	lifecycle := &recordingNodeLabelsLifecycle{calls: calls}
	observerErr := errors.New("observer failed")
	h := newNodeLabelsLaunchTestIntegration(t, lifecycle, calls,
		observeroption.WithOnServerInitFunc(func(observeroption.Server) error {
			calls.add("observer")
			return observerErr
		}),
	)

	require.ErrorIs(t, h.Launch(context.Background()), observerErr)
	require.Equal(t, []string{"start", "observer", "stop"}, calls.snapshot())
	require.Equal(t, 1, lifecycle.stops)
}

func newNodeLabelsLaunchTestIntegration(
	t *testing.T,
	lifecycle *recordingNodeLabelsLifecycle,
	calls *orderedCalls,
	observerOptions ...observeroption.Option,
) *hubbleIntegration {
	t.Helper()
	cfg := defaultConfig
	cfg.EnableHubble = true
	cfg.SocketPath = filepath.Join(t.TempDir(), "hubble.sock")

	return &hubbleIntegration{
		log:                   hivetest.Logger(t),
		directionalNodeLabels: lifecycle,
		nodeLocalStore:        node.NewTestLocalNodeStore(node.LocalNode{}),
		monitorAgent:          &recordingMonitorAgent{calls: calls},
		observerOptions:       observerOptions,
		grpcMetrics:           grpc_prometheus.NewServerMetrics(),
		config:                cfg,
	}
}
