// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// regenerationFailureReason indicates the reason of regeneration failure.
type regenerationFailureReason int

const (
	// regenerationFailureReasonNone represents a successful regeneration
	regenerationFailureReasonNone regenerationFailureReason = iota
	regenerationFailureReasonEndpointStateInvalid
	regenerationFailureReasonPrepareBuildError
	regenerationFailureReasonDatapathOrchestrationError
	regenerationFailureReasonBPFError
	regenerationFailureReasonProxyPolicyError
	regenerationFailureReasonPolicyBPFError
	regenerationFailureReasonEndpointPolicyUpdateError
	regenerationFailureReasonPolicyRegenerationError
	regenerationFailureReasonUnknown
)

func (r regenerationFailureReason) String() string {
	switch r {
	case regenerationFailureReasonEndpointStateInvalid:
		return "EndpointStateInvalid"
	case regenerationFailureReasonPrepareBuildError:
		return "PrepareBuildError"
	case regenerationFailureReasonDatapathOrchestrationError:
		return "DatapathOrchestrationError"
	case regenerationFailureReasonBPFError:
		return "BPFError"
	case regenerationFailureReasonProxyPolicyError:
		return "ProxyPolicyError"
	case regenerationFailureReasonPolicyBPFError:
		return "PolicyBPFError"
	case regenerationFailureReasonEndpointPolicyUpdateError:
		return "EndpointPolicyUpdateError"
	case regenerationFailureReasonPolicyRegenerationError:
		return "PolicyRegenerationError"
	case regenerationFailureReasonUnknown:
		return "Unknown"
	default:
		return ""
	}
}

// IsPolicyFailure indicates if the the regeneration failed due any policy related reason.
func (r regenerationFailureReason) IsPolicyFailure() bool {
	return r == regenerationFailureReasonPolicyRegenerationError ||
		r == regenerationFailureReasonEndpointPolicyUpdateError ||
		r == regenerationFailureReasonPolicyBPFError ||
		r == regenerationFailureReasonProxyPolicyError
}

// regenerationError is a custom error type for endpoint regeneration related failures.
type regenerationError struct {
	reason regenerationFailureReason
	err    error
}

func newRegenerationError(reason regenerationFailureReason, err error) *regenerationError {
	return &regenerationError{
		reason: reason,
		err:    err,
	}
}

func newRegenerationErrorf(reason regenerationFailureReason, format string, args ...any) *regenerationError {
	return &regenerationError{
		reason: reason,
		err:    fmt.Errorf(format, args...),
	}
}

func (re *regenerationError) GetReason() regenerationFailureReason {
	return re.reason
}

func (re *regenerationError) Error() string {
	return re.err.Error()
}

func (re *regenerationError) Unwrap() error {
	return re.err
}

// RegenerationContext provides context to regenerate() calls to determine
// the caller, and which specific aspects to regeneration are necessary to
// update the datapath to implement the new behavior.
type regenerationContext struct {
	// Reason provides context to source for the regeneration, which is
	// used to generate useful log messages.
	Reason regeneration.Reason

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

func ParseExternalRegenerationMetadata(ctx context.Context, logger *slog.Logger, c context.CancelFunc, e *regeneration.ExternalRegenerationMetadata) *regenerationContext {
	if e.RegenerationLevel == regeneration.Invalid {
		logger.Error("Uninitialized regeneration level", logfields.Reason, e.Reason)
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
	policyResult       *policyGenerateResult
	bpfHeaderfilesHash string
	epInfoCache        *epInfoCache
	proxyWaitGroup     *completion.WaitGroup
	ctCleaned          chan struct{}
	completionCtx      context.Context
	completionCancel   context.CancelFunc
	currentDir         string
	nextDir            string
	regenerationLevel  regeneration.DatapathRegenerationLevel

	policyMapSyncDone bool
	policyMapDump     policy.MapStateMap

	finalizeList revert.FinalizeList
	revertStack  revert.RevertStack
}

func (ctx *datapathRegenerationContext) prepareForProxyUpdates(parentCtx context.Context) {
	completionCtx, completionCancel := context.WithTimeout(parentCtx, EndpointGenerationTimeout)
	ctx.proxyWaitGroup = completion.NewWaitGroup(completionCtx)
	ctx.completionCtx = completionCtx
	ctx.completionCancel = completionCancel
}
