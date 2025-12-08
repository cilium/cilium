// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package debug

import (
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/common"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
)

// Parser is a parser for debug payloads
type Parser struct {
	log            *slog.Logger
	endpointGetter getters.EndpointGetter
	linkMonitor    getters.LinkGetter

	debugMsgDecoder options.DebugMsgDecoderFunc
}

// New creates a new parser
func New(log *slog.Logger, endpointGetter getters.EndpointGetter, opts ...options.Option) (*Parser, error) {
	args := &options.Options{
		DebugMsgDecoder: func(data []byte) (*monitor.DebugMsg, error) {
			dbg := &monitor.DebugMsg{}
			return dbg, dbg.Decode(data)
		},
	}
	for _, opt := range opts {
		opt(args)
	}
	return &Parser{
		log:             log,
		endpointGetter:  endpointGetter,
		debugMsgDecoder: args.DebugMsgDecoder,
	}, nil
}

// Decode takes the a debug event payload obtained from the perf event ring
// buffer and decodes it
func (p *Parser) Decode(data []byte, cpu int) (*flowpb.DebugEvent, error) {
	if len(data) == 0 {
		return nil, errors.ErrEmptyData
	}

	eventType := data[0]
	if eventType != api.MessageTypeDebug {
		return nil, errors.NewErrInvalidType(eventType)
	}

	dbg, err := p.debugMsgDecoder(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse debug event: %w", err)
	}

	decoded := &flowpb.DebugEvent{
		Type:    flowpb.DebugEventType(dbg.SubType),
		Source:  p.decodeEndpoint(dbg.Source),
		Hash:    wrapperspb.UInt32(dbg.Hash),
		Arg1:    wrapperspb.UInt32(dbg.Arg1),
		Arg2:    wrapperspb.UInt32(dbg.Arg2),
		Arg3:    wrapperspb.UInt32(dbg.Arg3),
		Cpu:     wrapperspb.Int32(int32(cpu)),
		Message: dbg.Message(p.linkMonitor),
	}

	return decoded, nil
}

func (p *Parser) decodeEndpoint(id uint16) *flowpb.Endpoint {
	if id == 0 {
		return nil
	}

	epId := uint32(id)
	if p.endpointGetter != nil {
		if ep, ok := p.endpointGetter.GetEndpointInfoByID(id); ok {
			labels := ep.GetLabels()
			return &flowpb.Endpoint{
				ID:          epId,
				Identity:    uint32(ep.GetIdentity()),
				ClusterName: (labels[k8sConst.PolicyLabelCluster]).Value,
				Namespace:   ep.GetK8sNamespace(),
				Labels:      common.SortAndFilterLabels(p.log, labels.GetModel(), ep.GetIdentity()),
				PodName:     ep.GetK8sPodName(),
			}
		}
	}

	return &flowpb.Endpoint{
		ID: epId,
	}
}
