// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package xdsclient

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/util/wait"
)

func mustMarshalAny(src proto.Message) *anypb.Any {
	res, err := anypb.New(src)
	if err != nil {
		panic(fmt.Errorf("marshal any: %w", err))
	}
	return res
}

func waitForCondition(ctx context.Context, t *testing.T, f func() error) error {
	stop := make(chan struct{})
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	var err error
	wait.Until(func() {
		t.Log("check function")
		err = f()
		if err == nil {
			t.Log("condition met, exiting")
			close(stop)
			return
		}
		t.Log("condition not met")
		select {
		case <-ctx.Done():
		case <-timeout.C:
		default:
			return
		}

		close(stop)
	}, 5*time.Second, stop)
	if err != nil {
		return fmt.Errorf("Waiting for condition failed, timeout occurred")
	}
	return nil
}
