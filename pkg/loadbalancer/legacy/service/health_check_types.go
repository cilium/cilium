// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

// Checker

type HealthChecker interface {
	SetCallback(cb HealthCheckCallbackFunc)
	UpsertService(svcAddr lb.L3n4Addr, name lb.ServiceName, svcType lb.SVCType, svcAnnotations map[string]string, backends []*lb.LegacyBackend)
	DeleteService(svcAddr lb.L3n4Addr, name lb.ServiceName)
}

const (
	HealthCheckCBSvcEvent = iota
	HealthCheckCBBackendEvent
)

type HealthCheckCBSvcEventData struct {
	SvcAddr lb.L3n4Addr
}

type HealthCheckCBBackendEventData struct {
	SvcAddr lb.L3n4Addr
	BeAddr  lb.L3n4Addr
	BeState lb.BackendState
}

type HealthCheckCallbackFunc func(event int, data any)

// Subscriber

type HealthUpdateSvcInfo struct {
	Name           lb.ServiceName
	Addr           lb.L3n4Addr
	SvcType        lb.SVCType
	ActiveBackends []lb.LegacyBackend
}

type HealthUpdateCallback func(svcInfo HealthUpdateSvcInfo)

type ServiceHealthCheckManager interface {
	// Subscribe allows subscribing to service health check related events.
	// The subscriber will receive updates on the callback as long as the passed
	// context is not done.
	Subscribe(ctx context.Context, callback HealthUpdateCallback)
}

type HealthSubscriber struct {
	Ctx      context.Context
	Callback HealthUpdateCallback
}
