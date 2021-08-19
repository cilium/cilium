// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Hubble

//go:build !privileged_tests
// +build !privileged_tests

package metrics

import (
	"context"
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"
)

func TestUninitializedMetrics(t *testing.T) {
	ProcessFlow(context.TODO(), &pb.Flow{})
}
