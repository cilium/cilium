// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides pcap recorder
var Cell = cell.Module(
	"recorder",
	"PCAP Recorder",

	cell.Provide(newRecorderWithLifecycle),
)

type recorderParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    logrus.FieldLogger

	AgentConfig *option.DaemonConfig
	Datapath    datapath.Datapath
}

func newRecorderWithLifecycle(params recorderParams) (*Recorder, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())

	recorder := newRecorder(ctx, params.Logger, params.Datapath.Loader())

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
