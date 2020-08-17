// Copyright 2016-2020 Authors of Cilium
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

// +build !privileged_tests

package k8s

import (
	"context"
	"net/http"
	"time"

	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *K8sSuite) Test_runHeartbeat(c *C) {
	// k8s api server never replied back in the expected time. We should close all connections
	k8smetrics.LastSuccessInteraction.Reset()
	time.Sleep(2 * time.Millisecond)

	testCtx, testCtxCancel := context.WithCancel(context.Background())

	called := make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			// Block any attempt to connect return from a heartbeat until the
			// test is complete.
			<-testCtx.Done()
			return nil
		},
		time.Millisecond,
		func() {
			close(called)
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err := testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))
	testCtxCancel()

	// There are some connectivity issues, cilium is trying to reach kube-apiserver
	// but it's only receiving errors for other requests. We should close all
	// connections!

	// Wait the double amount of time than the timeout to make sure
	// LastSuccessInteraction is not taken into account and we will see that we
	// will close all connections.
	testCtx, testCtxCancel = context.WithCancel(context.Background())
	time.Sleep(200 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			// Block any attempt to connect return from a heartbeat until the
			// test is complete.
			<-testCtx.Done()
			return nil
		},
		100*time.Millisecond,
		func() {
			close(called)
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err = testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))
	testCtxCancel()

	// Cilium is successfully talking with kube-apiserver, we should not do
	// anything.
	k8smetrics.LastSuccessInteraction.Reset()

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		100*time.Millisecond,
		func() {
			c.Error("This should not have been called!")
		},
	)

	select {
	case <-time.After(200 * time.Millisecond):
	case <-called:
		c.Error("Heartbeat should have closed all connections")
	}

	// Cilium had the last interaction with kube-apiserver a long time ago.
	// We should perform a heartbeat
	k8smetrics.LastInteraction.Reset()
	time.Sleep(500 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		100*time.Millisecond,
		func() {
			c.Error("This should not have been called!")
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err = testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))

	// Cilium had the last interaction with kube-apiserver a long time ago.
	// We should perform a heartbeat but the heart beat will return
	// an error so we should close all connections
	k8smetrics.LastInteraction.Reset()
	time.Sleep(500 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		func(ctx context.Context) error {
			return &errors.StatusError{
				ErrStatus: metav1.Status{
					Code: http.StatusRequestTimeout,
				},
			}
		},
		100*time.Millisecond,
		func() {
			close(called)
		},
	)

	// We need to polling for the condition instead of using a time.After to
	// give the opportunity for scheduler to run the go routine inside runHeartbeat
	err = testutils.WaitUntil(func() bool {
		select {
		case <-called:
			return true
		default:
			return false
		}
	},
		5*time.Second)
	c.Assert(err, IsNil, Commentf("Heartbeat should have closed all connections"))
}
