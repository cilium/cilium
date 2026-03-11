// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"log/slog"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	defaultProbeInterval       = 5 * time.Second
	defaultProbeTimeout        = 2 * time.Second
	defaultFailureThreshold    = 3
	defaultSuccessThreshold    = 3
	defaultMinFailoverInterval = 30 * time.Second
	maxFailoverInterval        = 5 * time.Minute
	flappingResetPeriod        = 10 * time.Minute
)

// failoverEvent is sent from the health monitor to the reconciler when a
// failover should occur for a given endpoint.
type failoverEvent struct {
	endpointName string
	newRole      string // "primary" or "standby"
}

// vtepHealthMonitor performs periodic ICMP health checking of VTEP endpoints
// that have standby connections configured. It communicates failover decisions
// to the reconciler via a channel.
type vtepHealthMonitor struct {
	logger              *slog.Logger
	mu                  lock.Mutex
	states              map[string]*endpointFailoverState
	failoverCh          chan failoverEvent
	probeInterval       time.Duration
	probeTimeout        time.Duration
	failureThreshold    int
	successThreshold    int
	minFailoverInterval time.Duration
}

// endpointFailoverState tracks the health and failover state for a single
// VTEP endpoint that has a standby connection configured.
type endpointFailoverState struct {
	endpointName string

	// Current active role: "primary" or "standby"
	currentRole string

	// Primary connection info (from CRD spec)
	primaryTunnelEndpoint string
	primaryMAC            string

	// Standby connection info (from CRD spec)
	standbyTunnelEndpoint string
	standbyMAC            string

	// CIDR for BPF map key
	cidr string

	// Health tracking
	primaryConsecutiveFailures  int
	primaryConsecutiveSuccesses int
	primaryHealthy              bool
	primaryLastProbeTime        time.Time
	primaryLastSuccessTime      time.Time
	primaryLatencyMs            int64

	standbyConsecutiveFailures  int
	standbyConsecutiveSuccesses int
	standbyHealthy              bool
	standbyLastProbeTime        time.Time
	standbyLastSuccessTime      time.Time
	standbyLatencyMs            int64

	// Failover tracking
	lastFailoverTime    time.Time
	failoverCount       int32
	minFailoverInterval time.Duration
	lastStableTime      time.Time // last time with no failover for flapping reset
}

// newVTEPHealthMonitor creates a new health monitor instance.
func newVTEPHealthMonitor(logger *slog.Logger, failoverCh chan failoverEvent) *vtepHealthMonitor {
	return &vtepHealthMonitor{
		logger:              logger,
		states:              make(map[string]*endpointFailoverState),
		failoverCh:          failoverCh,
		probeInterval:       defaultProbeInterval,
		probeTimeout:        defaultProbeTimeout,
		failureThreshold:    defaultFailureThreshold,
		successThreshold:    defaultSuccessThreshold,
		minFailoverInterval: defaultMinFailoverInterval,
	}
}

// updateEndpoints updates the set of endpoints being monitored.
// Only endpoints with a standby connection are monitored.
func (m *vtepHealthMonitor) updateEndpoints(endpoints []cilium_api_v2.VTEPEndpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Track which endpoints are still present
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.Standby == nil {
			// No standby — no monitoring needed
			continue
		}

		seen[ep.Name] = true

		state, exists := m.states[ep.Name]
		if !exists {
			// New endpoint with standby — initialize state
			state = &endpointFailoverState{
				endpointName:          ep.Name,
				currentRole:           "primary",
				primaryTunnelEndpoint: ep.TunnelEndpoint,
				primaryMAC:            ep.MAC,
				standbyTunnelEndpoint: ep.Standby.TunnelEndpoint,
				standbyMAC:            ep.Standby.MAC,
				cidr:                  ep.CIDR,
				primaryHealthy:        true, // Assume healthy until proven otherwise
				standbyHealthy:        true,
				minFailoverInterval:   m.minFailoverInterval,
				lastStableTime:        time.Now(),
			}
			m.states[ep.Name] = state
			m.logger.Info("Started health monitoring for VTEP endpoint",
				logfields.Name, ep.Name,
				"primaryTunnelEndpoint", ep.TunnelEndpoint,
				"standbyTunnelEndpoint", ep.Standby.TunnelEndpoint)
		} else {
			// Update connection info if changed
			state.primaryTunnelEndpoint = ep.TunnelEndpoint
			state.primaryMAC = ep.MAC
			state.standbyTunnelEndpoint = ep.Standby.TunnelEndpoint
			state.standbyMAC = ep.Standby.MAC
			state.cidr = ep.CIDR
		}
	}

	// Remove endpoints that are no longer present or no longer have standby
	for name := range m.states {
		if !seen[name] {
			m.logger.Info("Stopped health monitoring for VTEP endpoint",
				logfields.Name, name)
			delete(m.states, name)
		}
	}
}

// probe performs ICMP health probes for all monitored endpoints.
// This method is called periodically by the job.Timer.
func (m *vtepHealthMonitor) probe(ctx context.Context) error {
	m.mu.Lock()
	endpoints := make([]*endpointFailoverState, 0, len(m.states))
	for _, state := range m.states {
		endpoints = append(endpoints, state)
	}
	m.mu.Unlock()

	if len(endpoints) == 0 {
		return nil
	}

	// Probe all endpoints in parallel
	var wg sync.WaitGroup
	for _, state := range endpoints {
		wg.Add(1)
		go func(s *endpointFailoverState) {
			defer wg.Done()
			m.probeEndpoint(ctx, s)
		}(state)
	}
	wg.Wait()

	return nil
}

// probeEndpoint probes both the primary and standby connections for a single endpoint.
func (m *vtepHealthMonitor) probeEndpoint(ctx context.Context, state *endpointFailoverState) {
	// Snapshot IPs under lock to avoid data race with updateEndpoints()
	m.mu.Lock()
	primaryIP := state.primaryTunnelEndpoint
	standbyIP := state.standbyTunnelEndpoint
	m.mu.Unlock()

	// Probe both connections in parallel
	var wg sync.WaitGroup
	var primaryOk bool
	var primaryLatency int64
	var standbyOk bool
	var standbyLatency int64

	wg.Add(2)
	go func() {
		defer wg.Done()
		primaryOk, primaryLatency = m.icmpProbe(ctx, primaryIP)
	}()
	go func() {
		defer wg.Done()
		standbyOk, standbyLatency = m.icmpProbe(ctx, standbyIP)
	}()
	wg.Wait()

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update primary health state
	state.primaryLastProbeTime = now
	if primaryOk {
		state.primaryConsecutiveFailures = 0
		state.primaryConsecutiveSuccesses++
		state.primaryLastSuccessTime = now
		state.primaryLatencyMs = primaryLatency
		if state.primaryConsecutiveSuccesses >= m.successThreshold {
			state.primaryHealthy = true
		}
	} else {
		state.primaryConsecutiveSuccesses = 0
		state.primaryConsecutiveFailures++
		if state.primaryConsecutiveFailures >= m.failureThreshold {
			state.primaryHealthy = false
		}
	}

	// Update standby health state
	state.standbyLastProbeTime = now
	if standbyOk {
		state.standbyConsecutiveFailures = 0
		state.standbyConsecutiveSuccesses++
		state.standbyLastSuccessTime = now
		state.standbyLatencyMs = standbyLatency
		if state.standbyConsecutiveSuccesses >= m.successThreshold {
			state.standbyHealthy = true
		}
	} else {
		state.standbyConsecutiveSuccesses = 0
		state.standbyConsecutiveFailures++
		if state.standbyConsecutiveFailures >= m.failureThreshold {
			state.standbyHealthy = false
		}
	}

	// Reset flapping counters after stable period
	if now.Sub(state.lastFailoverTime) > flappingResetPeriod && state.failoverCount > 0 {
		state.minFailoverInterval = m.minFailoverInterval
		state.lastStableTime = now
	}

	// Check if failover is needed
	m.checkFailover(state, now)
}

// checkFailover evaluates whether a failover should be triggered.
// Must be called with m.mu held.
func (m *vtepHealthMonitor) checkFailover(state *endpointFailoverState, now time.Time) {
	// Check cooldown
	if !state.lastFailoverTime.IsZero() && now.Sub(state.lastFailoverTime) < state.minFailoverInterval {
		return
	}

	var newRole string

	switch state.currentRole {
	case "primary":
		// Failover to standby if primary is down and standby is healthy
		if !state.primaryHealthy && state.standbyHealthy {
			newRole = "standby"
		}
	case "standby":
		// Failover back to primary if standby is down and primary is healthy
		if !state.standbyHealthy && state.primaryHealthy {
			newRole = "primary"
		}
	}

	if newRole == "" {
		return
	}

	m.logger.Warn("VTEP failover triggered",
		logfields.Name, state.endpointName,
		"from", state.currentRole,
		"to", newRole,
		"failoverCount", state.failoverCount+1)

	state.currentRole = newRole
	state.lastFailoverTime = now
	state.failoverCount++

	// Exponential backoff for flapping protection
	state.minFailoverInterval *= 2
	if state.minFailoverInterval > maxFailoverInterval {
		state.minFailoverInterval = maxFailoverInterval
	}

	// Send failover event (non-blocking — if channel is full, log and skip)
	select {
	case m.failoverCh <- failoverEvent{
		endpointName: state.endpointName,
		newRole:      newRole,
	}:
	default:
		m.logger.Error("Failover channel full, dropping failover event",
			logfields.Name, state.endpointName,
			"newRole", newRole)
	}
}

// icmpProbe sends an ICMP ping to the given IP and returns (ok, latencyMs).
func (m *vtepHealthMonitor) icmpProbe(ctx context.Context, ip string) (bool, int64) {
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		m.logger.Debug("Failed to create pinger", "ip", ip, logfields.Error, err)
		return false, 0
	}

	pinger.SetPrivileged(true)
	pinger.Count = 1
	pinger.Timeout = m.probeTimeout
	pinger.Interval = m.probeTimeout // Only 1 packet, interval doesn't matter

	var latencyMs int64

	pinger.OnRecv = func(pkt *probing.Packet) {
		pinger.Stop()
	}

	pinger.OnFinish = func(stats *probing.Statistics) {
		if stats.PacketsRecv > 0 && len(stats.Rtts) > 0 {
			latencyMs = stats.Rtts[0].Milliseconds()
		}
	}

	err = pinger.RunWithContext(ctx)
	if err != nil {
		m.logger.Debug("ICMP probe failed", "ip", ip, logfields.Error, err)
		return false, 0
	}

	stats := pinger.Statistics()
	return stats.PacketsRecv > 0, latencyMs
}

// resetAllState resets all endpoints back to primary with fresh health state
// and cleared cooldown/failover counters. Called on manual failover reset.
func (m *vtepHealthMonitor) resetAllState() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, state := range m.states {
		m.logger.Info("Resetting failover state to primary",
			logfields.Name, state.endpointName,
			"previousRole", state.currentRole,
			"previousFailoverCount", state.failoverCount)

		state.currentRole = "primary"
		state.failoverCount = 0
		state.lastFailoverTime = time.Time{}
		state.minFailoverInterval = m.minFailoverInterval
		state.lastStableTime = time.Now()

		// Reset health counters — assume healthy until probes say otherwise
		state.primaryHealthy = true
		state.primaryConsecutiveFailures = 0
		state.primaryConsecutiveSuccesses = 0
		state.standbyHealthy = true
		state.standbyConsecutiveFailures = 0
		state.standbyConsecutiveSuccesses = 0
	}
}

// getCurrentRole returns the current active role for an endpoint.
func (m *vtepHealthMonitor) getCurrentRole(endpointName string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[endpointName]
	if !ok {
		return "primary"
	}
	return state.currentRole
}

// setCurrentRole sets the active role for an endpoint (used by reconciler
// during config-change-aware updates).
func (m *vtepHealthMonitor) setCurrentRole(endpointName string, role string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[endpointName]
	if !ok {
		return
	}
	state.currentRole = role
}

// getActiveConnection returns the tunnel endpoint and MAC of the currently
// active connection for the given endpoint. If the endpoint has no standby
// configured (not tracked), it returns the primary connection info.
func (m *vtepHealthMonitor) getActiveConnection(ep cilium_api_v2.VTEPEndpoint) (tunnelEndpoint string, mac string) {
	if ep.Standby == nil {
		return ep.TunnelEndpoint, ep.MAC
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[ep.Name]
	if !ok || state.currentRole == "primary" {
		return ep.TunnelEndpoint, ep.MAC
	}
	return ep.Standby.TunnelEndpoint, ep.Standby.MAC
}

// buildEndpointHealthStatus builds status fields for an endpoint from the
// current health state. Returns nil health statuses if endpoint is not monitored.
func (m *vtepHealthMonitor) buildEndpointHealthStatus(endpointName string) (
	activeRole string,
	primaryHealth *cilium_api_v2.VTEPConnectionHealth,
	standbyHealth *cilium_api_v2.VTEPConnectionHealth,
	lastFailoverTime *time.Time,
	failoverCount int32,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.states[endpointName]
	if !ok {
		return "", nil, nil, nil, 0
	}

	activeRole = state.currentRole

	primaryHealth = buildConnectionHealth(
		state.primaryTunnelEndpoint,
		state.primaryHealthy,
		state.primaryLastProbeTime,
		state.primaryLastSuccessTime,
		state.primaryLatencyMs,
		state.primaryConsecutiveFailures,
	)

	standbyHealth = buildConnectionHealth(
		state.standbyTunnelEndpoint,
		state.standbyHealthy,
		state.standbyLastProbeTime,
		state.standbyLastSuccessTime,
		state.standbyLatencyMs,
		state.standbyConsecutiveFailures,
	)

	if !state.lastFailoverTime.IsZero() {
		t := state.lastFailoverTime
		lastFailoverTime = &t
	}
	failoverCount = state.failoverCount

	return
}

// buildConnectionHealth converts internal health state to the CRD status struct.
func buildConnectionHealth(
	tunnelEndpoint string,
	healthy bool,
	lastProbeTime time.Time,
	lastSuccessTime time.Time,
	latencyMs int64,
	consecutiveFailures int,
) *cilium_api_v2.VTEPConnectionHealth {
	h := &cilium_api_v2.VTEPConnectionHealth{
		TunnelEndpoint:      tunnelEndpoint,
		Healthy:             healthy,
		LatencyMs:           latencyMs,
		ConsecutiveFailures: consecutiveFailures,
	}
	if !lastProbeTime.IsZero() {
		t := metav1.NewTime(lastProbeTime)
		h.LastProbeTime = &t
	}
	if !lastSuccessTime.IsZero() {
		t := metav1.NewTime(lastSuccessTime)
		h.LastSuccessTime = &t
	}
	return h
}
