// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// monitorFilter is an implementation of OnMonitorEvent interface that filters monitor events.
type monitorFilter struct {
	logger logrus.FieldLogger

	drop          bool
	debug         bool
	capture       bool
	trace         bool
	l7            bool
	agent         bool
	policyVerdict bool
	recCapture    bool
	traceSock     bool
}

// NewMonitorFilter creates a new monitor filter.
// If monitorEventFilters is empty, no events are allowed.
func NewMonitorFilter(logger logrus.FieldLogger, monitorEventFilters []string) (*monitorFilter, error) {
	monitorFilter := monitorFilter{logger: logger}

	for _, filter := range monitorEventFilters {
		switch filter {
		case monitorAPI.MessageTypeNameDrop:
			monitorFilter.drop = true
		case monitorAPI.MessageTypeNameDebug:
			monitorFilter.debug = true
		case monitorAPI.MessageTypeNameCapture:
			monitorFilter.capture = true
		case monitorAPI.MessageTypeNameTrace:
			monitorFilter.trace = true
		case monitorAPI.MessageTypeNameL7:
			monitorFilter.l7 = true
		case monitorAPI.MessageTypeNameAgent:
			monitorFilter.agent = true
		case monitorAPI.MessageTypeNamePolicyVerdict:
			monitorFilter.policyVerdict = true
		case monitorAPI.MessageTypeNameRecCapture:
			monitorFilter.recCapture = true
		case monitorAPI.MessageTypeNameTraceSock:
			monitorFilter.traceSock = true
		default:
			return nil, fmt.Errorf("unknown monitor event type: %s", filter)
		}
	}

	logger.WithField("filters", monitorEventFilters).Info("Configured Hubble with monitor event filters")
	return &monitorFilter, nil
}

// OnMonitorEvent implements observeroption.OnMonitorEvent interface
// It returns true if an event is to be dropped, false otherwise.
func (m *monitorFilter) OnMonitorEvent(ctx context.Context, event *observerTypes.MonitorEvent) (bool, error) {
	switch payload := event.Payload.(type) {
	case *observerTypes.PerfEvent:
		if len(payload.Data) == 0 {
			return true, errors.ErrEmptyData
		}

		switch payload.Data[0] {
		case monitorAPI.MessageTypeDrop:
			return !m.drop, nil
		case monitorAPI.MessageTypeDebug:
			return !m.debug, nil
		case monitorAPI.MessageTypeCapture:
			return !m.capture, nil
		case monitorAPI.MessageTypeTrace:
			return !m.trace, nil
		case monitorAPI.MessageTypeAccessLog: // MessageTypeAccessLog maps to MessageTypeNameL7
			return !m.l7, nil
		case monitorAPI.MessageTypePolicyVerdict:
			return !m.policyVerdict, nil
		case monitorAPI.MessageTypeRecCapture:
			return !m.recCapture, nil
		case monitorAPI.MessageTypeTraceSock:
			return !m.traceSock, nil
		default:
			return true, errors.ErrUnknownEventType
		}
	case *observerTypes.AgentEvent:
		return !m.agent, nil
	case nil:
		return true, errors.ErrEmptyData
	default:
		return true, errors.ErrUnknownEventType
	}
}
