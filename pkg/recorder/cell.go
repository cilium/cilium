// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	recorderapi "github.com/cilium/cilium/api/v1/server/restapi/recorder"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides pcap recorder
var Cell = cell.Module(
	"recorder",
	"PCAP Recorder",

	cell.Provide(newRecorderWithLifecycle),
	cell.Provide(newRecorderApiHandler),
)

type recorderParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger

	AgentConfig  *option.DaemonConfig
	Orchestrator datapath.Orchestrator
}

func newRecorderWithLifecycle(params recorderParams) (*Recorder, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())

	recorder := newRecorder(ctx, params.Logger, params.Orchestrator)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			if params.AgentConfig.EnableRecorder {
				if err := recorder.enableRecorder(); err != nil {
					return fmt.Errorf("failed to enable recorder: %w", err)
				}
			}
			return nil
		},
		OnStop: func(hookContext cell.HookContext) error {
			cancelCtx()
			return nil
		},
	})

	return recorder, nil
}

type recorderApiHandlerOut struct {
	cell.Out

	GetRecorderHandler      recorderapi.GetRecorderHandler
	GetRecorderIDHandler    recorderapi.GetRecorderIDHandler
	GetRecorderMasksHandler recorderapi.GetRecorderMasksHandler
	PutRecorderIDHandler    recorderapi.PutRecorderIDHandler
	DeleteRecorderIDHandler recorderapi.DeleteRecorderIDHandler
}

func newRecorderApiHandler(logger *slog.Logger, recorder *Recorder) recorderApiHandlerOut {
	return recorderApiHandlerOut{
		GetRecorderHandler:      &getRecorderHandler{logger: logger, recorder: recorder},
		GetRecorderIDHandler:    &getRecorderIDHandler{logger: logger, recorder: recorder},
		GetRecorderMasksHandler: &getRecorderMasksHandler{logger: logger, recorder: recorder},
		PutRecorderIDHandler:    &putRecorderIDHandler{logger: logger, recorder: recorder},
		DeleteRecorderIDHandler: &deleteRecorderIDHandler{logger: logger, recorder: recorder},
	}
}
