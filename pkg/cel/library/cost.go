// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library

import (
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types/ref"
)

// k8s label values are bounded by 63 characters (RFC 1035 / k8s validation).
// Providing ResultSize prevents CEL from using math.MaxUint64 as the default
// string length bound when computing downstream costs (e.g. == comparisons).
const maxLabelValueLen = 63

// CostEstimator provides static (compile-time) and runtime cost estimates for
// the cilium's CEL library functions.
//
// It implements both checker.CostEstimator (for env.EstimateCost) and
// interpreter.ActualCostEstimator (for cel.CostTracking). For any function not
// belonging to this library the methods return nil, delegating cost accounting
// to CEL's built-in model which covers all standard library functions.
//
// The static estimates must bound the actual runtime costs (CEL requirement):
//
//	__label_make__                  static 1, runtime 1  (struct construction)
//	__label_matcher_lookup_label__  static 1, runtime 1  (single map/array access)
//	__label_matcher_lookup_key__    static 1–2, runtime 2 (string parse + access)
type CostEstimator struct{}

// EstimateSize returns nil for all nodes, deferring to CEL's built-in size model.
func (CostEstimator) EstimateSize(_ checker.AstNode) *checker.SizeEstimate {
	return nil
}

// EstimateCallCost returns compile-time cost bounds for library overloads.
func (CostEstimator) EstimateCallCost(_, overloadID string, _ *checker.AstNode, _ []checker.AstNode) *checker.CallEstimate {
	switch overloadID {
	case LabelMatcherLookupLabelFuncName:
		// Pre-parsed label lookup: single map/array access.
		return &checker.CallEstimate{
			CostEstimate: checker.CostEstimate{Min: 1, Max: 1},
			ResultSize:   &checker.SizeEstimate{Min: 0, Max: maxLabelValueLen},
		}
	case LabelMatcherLookupKeyFuncName:
		// Runtime-parse lookup: parse label string then access.
		return &checker.CallEstimate{
			CostEstimate: checker.CostEstimate{Min: 1, Max: 2},
			ResultSize:   &checker.SizeEstimate{Min: 0, Max: maxLabelValueLen},
		}
	case LabelMakeFuncName:
		// Label construction from pre-split string constants.
		return &checker.CallEstimate{
			CostEstimate: checker.CostEstimate{Min: 1, Max: 1},
		}
	}
	return nil
}

// CallCost returns the actual runtime cost for label matcher overloads.
func (CostEstimator) CallCost(_, overloadID string, _ []ref.Val, _ ref.Val) *uint64 {
	var cost uint64
	switch overloadID {
	case LabelMatcherLookupLabelFuncName:
		cost = 1
	case LabelMatcherLookupKeyFuncName:
		cost = 2
	case LabelMakeFuncName:
		cost = 1
	default:
		return nil
	}
	return &cost
}
