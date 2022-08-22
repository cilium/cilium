// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/fx"
	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sClientSuite struct{}

var _ = Suite(&K8sClientSuite{})

func (s *K8sClientSuite) Test_runHeartbeat(c *C) {
	// k8s api server never replied back in the expected time. We should close all connections
	k8smetrics.LastSuccessInteraction.Reset()
	time.Sleep(2 * time.Millisecond)

	testCtx, testCtxCancel := context.WithCancel(context.Background())

	called := make(chan struct{})
	runHeartbeat(
		logging.DefaultLogger,
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
	time.Sleep(20 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		logging.DefaultLogger,
		func(ctx context.Context) error {
			// Block any attempt to connect return from a heartbeat until the
			// test is complete.
			<-testCtx.Done()
			return nil
		},
		10*time.Millisecond,
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
		logging.DefaultLogger,
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		10*time.Millisecond,
		func() {
			c.Error("This should not have been called!")
		},
	)

	select {
	case <-time.After(20 * time.Millisecond):
	case <-called:
		c.Error("Heartbeat should have closed all connections")
	}

	// Cilium had the last interaction with kube-apiserver a long time ago.
	// We should perform a heartbeat
	k8smetrics.LastInteraction.Reset()
	time.Sleep(50 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		logging.DefaultLogger,
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		10*time.Millisecond,
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
	time.Sleep(50 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		logging.DefaultLogger,
		func(ctx context.Context) error {
			return &errors.StatusError{
				ErrStatus: metav1.Status{
					Code: http.StatusRequestTimeout,
				},
			}
		},
		10*time.Millisecond,
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

func (s *K8sClientSuite) Test_client(c *C) {
	requests := map[string]*http.Request{}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests[r.URL.Path] = r
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	}))
	srv.Start()
	defer srv.Close()

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)

	var clientset Clientset
	hive := hive.New(
		viper.New(),
		flags,

		Cell,
		hive.NewCell("", fx.Populate(&clientset)),
	)

	// Set the config option via flags to check it's been registered.
	flags.Set(option.K8sAPIServer, srv.URL)

	app, err := hive.TestApp(c)
	c.Assert(err, IsNil)

	app.RequireStart()

	// Check that we see the connection probe
	c.Assert(requests["/api/v1/namespaces/kube-system"], NotNil)

	// Test that all different clientsets are wired correctly.
	_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(requests["/api/v1/namespaces/test/pods/pod"], NotNil)

	_, err = clientset.Slim().CoreV1().Pods("test").Get(context.TODO(), "slim-pod", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(requests["/api/v1/namespaces/test/pods/slim-pod"], NotNil)

	_, err = clientset.ExtensionsV1beta1().DaemonSets("test").Get(context.TODO(), "ds", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(requests["/apis/extensions/v1beta1/namespaces/test/daemonsets/ds"], NotNil)

	_, err = clientset.CiliumV2().CiliumEndpoints("test").Get(context.TODO(), "ces", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(requests["/apis/cilium.io/v2/namespaces/test/ciliumendpoints/ces"], NotNil)

	app.RequireStop()

	c.Assert(len(requests), Equals, 5)
}
