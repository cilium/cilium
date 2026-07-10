// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"errors"
	"log/slog"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var _ FlowProcessor = (*StaticFlowProcessor)(nil)

type StaticFlowProcessor struct {
	logger  *slog.Logger
	metrics []api.NamedHandler
}

func NewStaticFlowProcessor(logger *slog.Logger, metrics []api.NamedHandler) *StaticFlowProcessor {
	return &StaticFlowProcessor{
		logger:  logger,
		metrics: metrics,
	}
}

// ProcessFlow implements FlowProcessor.
func (p *StaticFlowProcessor) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	_, err := p.OnDecodedFlow(ctx, flow)
	return err
}

// OnDecodedFlow implements observeroption.OnDecodedFlow.
func (p *StaticFlowProcessor) OnDecodedFlow(ctx context.Context, flow *flowpb.Flow) (bool, error) {
	if len(p.metrics) == 0 {
		return false, nil
	}

	var errs error
	for _, nh := range p.metrics {
		// Continue running the remaining metrics handlers, since one failing
		// shouldn't impact the other metrics handlers.
		errs = errors.Join(errs, nh.Handler.ProcessFlow(ctx, flow))
	}
	if errs != nil {
		p.logger.Error("Failed to ProcessFlow in metrics handler", logfields.Error, errs)
	}
	return false, nil
}
