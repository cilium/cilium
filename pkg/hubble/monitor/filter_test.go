// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestNewMonitorFilter(t *testing.T) {
	logger, hook := test.NewNullLogger()

	tests := []struct {
		name        string
		filters     []string
		expectedErr error
		expectedMF  *monitorFilter
	}{
		{
			name:        "unknown filter",
			filters:     []string{"unknown"},
			expectedErr: fmt.Errorf("unknown monitor event type: unknown"),
			expectedMF:  nil,
		},
		{
			name: "valid filters",
			filters: []string{
				monitorAPI.MessageTypeNameDrop,
				monitorAPI.MessageTypeNameDebug,
				monitorAPI.MessageTypeNameCapture,
				monitorAPI.MessageTypeNameTrace,
				monitorAPI.MessageTypeNameL7,
				monitorAPI.MessageTypeNameAgent,
				monitorAPI.MessageTypeNamePolicyVerdict,
				monitorAPI.MessageTypeNameRecCapture,
				monitorAPI.MessageTypeNameTraceSock,
			},
			expectedErr: nil,
			expectedMF: &monitorFilter{
				logger: logger,

				drop:          true,
				debug:         true,
				capture:       true,
				trace:         true,
				l7:            true,
				agent:         true,
				policyVerdict: true,
				recCapture:    true,
				traceSock:     true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mf, err := NewMonitorFilter(logger, tc.filters)
			assert.Equal(t, tc.expectedErr, err)
			assert.Equal(t, tc.expectedMF, mf)

			if tc.expectedMF != nil {
				assert.Equal(t, 1, len(hook.Entries))
				assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
				assert.Equal(t, "Configured Hubble with monitor event filters", hook.LastEntry().Message)
				assert.Equal(t, tc.filters, hook.LastEntry().Data["filters"])
			}

			hook.Reset()
		})
	}
}

type testEvent struct {
	event       *observerTypes.MonitorEvent
	allowed     bool
	expectedErr error
}

func Test_OnMonitorEvent(t *testing.T) {
	logger, _ := test.NewNullLogger()

	tt := []struct {
		name    string
		filters []string
		events  []testEvent
	}{
		{
			name:    "nil payload",
			filters: []string{},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: nil,
					},
					allowed:     false,
					expectedErr: errors.ErrEmptyData,
				},
			},
		},
		{
			name:    "unknown event type",
			filters: []string{},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &struct{}{},
					},
					allowed:     false,
					expectedErr: errors.ErrUnknownEventType,
				},
			},
		},
		{
			name:    "unknown observerTypes.AgentEvent",
			filters: []string{},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{0xff},
						},
					},
					allowed:     false,
					expectedErr: errors.ErrUnknownEventType,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeAgent",
			filters: []string{monitorAPI.MessageTypeNameAgent},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.AgentEvent{
							Type: monitorAPI.MessageTypeAgent,
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeAccessLog",
			filters: []string{monitorAPI.MessageTypeNameL7},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeAccessLog},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "empty observerTypes.PerfEvent",
			filters: []string{},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{},
						},
					},
					allowed:     false,
					expectedErr: errors.ErrEmptyData,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeDrop",
			filters: []string{monitorAPI.MessageTypeNameDrop},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDrop},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeDebug",
			filters: []string{monitorAPI.MessageTypeNameDebug},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDebug},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeCapture",
			filters: []string{monitorAPI.MessageTypeNameCapture},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeCapture},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeTrace",
			filters: []string{monitorAPI.MessageTypeNameTrace},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeTrace},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypePolicyVerdict",
			filters: []string{monitorAPI.MessageTypeNamePolicyVerdict},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypePolicyVerdict},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeRecCapture",
			filters: []string{monitorAPI.MessageTypeNameRecCapture},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeRecCapture},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeTraceSock",
			filters: []string{monitorAPI.MessageTypeNameTraceSock},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeTraceSock},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
			},
		},
		{
			name:    fmt.Sprintf("composite filter with %s,%s", monitorAPI.MessageTypeNameDebug, monitorAPI.MessageTypeNameTrace),
			filters: []string{monitorAPI.MessageTypeNameDebug, monitorAPI.MessageTypeNameTrace},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeTrace},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDebug},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeCapture},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
			},
		},
		{
			name:    fmt.Sprintf("composite filter with %s,%s", monitorAPI.MessageTypeNameDebug, monitorAPI.MessageTypeNamePolicyVerdict),
			filters: []string{monitorAPI.MessageTypeNameDebug, monitorAPI.MessageTypeNamePolicyVerdict},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDebug},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypePolicyVerdict},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeTrace},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDrop},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
			},
		},
		{
			name:    fmt.Sprintf("composite filter with %s,%s", monitorAPI.MessageTypeNameCapture, monitorAPI.MessageTypeNameTrace),
			filters: []string{monitorAPI.MessageTypeNameCapture, monitorAPI.MessageTypeNameTrace},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeCapture},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeTrace},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDrop},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDebug},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
			},
		},
		{
			name:    "monitorAPI.MessageTypeNamePolicyVerdict should drop everything else except monitorAPI.MessageTypePolicyVerdict",
			filters: []string{monitorAPI.MessageTypeNamePolicyVerdict},
			events: []testEvent{
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDrop},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeDebug},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeCapture},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeTrace},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypePolicyVerdict},
						},
					},
					allowed:     true,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.PerfEvent{
							Data: []byte{monitorAPI.MessageTypeTraceSock},
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.AgentEvent{
							Type: monitorAPI.MessageTypeAccessLog,
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
				{
					event: &observerTypes.MonitorEvent{
						Payload: &observerTypes.AgentEvent{
							Type: monitorAPI.MessageTypeAgent,
						},
					},
					allowed:     false,
					expectedErr: nil,
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mf, err := NewMonitorFilter(logger, tc.filters)
			assert.NoError(t, err)

			for _, event := range tc.events {
				allowed, err := mf.OnMonitorEvent(context.Background(), event.event)
				assert.Equal(t, event.expectedErr, err)
				assert.Equal(t, event.allowed, allowed)
			}
		})
	}
}
