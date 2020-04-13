// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	"context"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/revert"
)

// RegenerationContext provides context to regenerate() calls to determine
// the caller, and which specific aspects to regeneration are necessary to
// update the datapath to implement the new behavior.
type regenerationContext struct {
	// Reason provides context to source for the regeneration, which is
	// used to generate useful log messages.
	Reason string

	// Stats are collected during the endpoint regeneration and provided
	// back to the caller
	Stats regenerationStatistics

	// DoneFunc must be called when the most resource intensive portion of
	// the regeneration is done
	DoneFunc func()

	datapathRegenerationContext *datapathRegenerationContext

	parentContext context.Context

	cancelFunc context.CancelFunc
}

func ParseExternalRegenerationMetadata(ctx context.Context, c context.CancelFunc, e *regeneration.ExternalRegenerationMetadata) *regenerationContext {
	if e.RegenerationLevel == regeneration.Invalid {
		log.WithField(logfields.Reason, e.Reason).Errorf("Uninitialized regeneration level")
	}

	return &regenerationContext{
		Reason: e.Reason,
		datapathRegenerationContext: &datapathRegenerationContext{
			regenerationLevel: e.RegenerationLevel,
			ctCleaned:         make(chan struct{}),
		},
		parentContext: ctx,
		cancelFunc:    c,
	}
}

// datapathRegenerationContext contains information related to regenerating the
// datapath (BPF, proxy, etc.).
type datapathRegenerationContext struct {
	bpfHeaderfilesHash string
	epInfoCache        *epInfoCache
	proxyWaitGroup     *completion.WaitGroup
	ctCleaned          chan struct{}
	completionCtx      context.Context
	completionCancel   context.CancelFunc
	currentDir         string
	nextDir            string
	regenerationLevel  regeneration.DatapathRegenerationLevel

	finalizeList revert.FinalizeList
	revertStack  revert.RevertStack
}

func (ctx *datapathRegenerationContext) prepareForProxyUpdates(parentCtx context.Context) {
	completionCtx, completionCancel := context.WithTimeout(parentCtx, EndpointGenerationTimeout)
	ctx.proxyWaitGroup = completion.NewWaitGroup(completionCtx)
	ctx.completionCtx = completionCtx
	ctx.completionCancel = completionCancel
}
