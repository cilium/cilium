// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
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
	// give the opportunity for scheduler to run the goroutine inside runHeartbeat
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
	// give the opportunity for scheduler to run the goroutine inside runHeartbeat
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
	// give the opportunity for scheduler to run the goroutine inside runHeartbeat
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
	// give the opportunity for scheduler to run the goroutine inside runHeartbeat
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
	requests := sync.Map{}
	getRequest := func(k string) *http.Request {
		v, ok := requests.Load(k)
		if !ok {
			return nil
		}
		return v.(*http.Request)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Store(r.URL.Path, r)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{
			       "major": "1",
			       "minor": "99"
			}`))
		default:
			w.Write([]byte("{}"))
		}
	}))
	srv.Start()
	defer srv.Close()

	var clientset Clientset
	hive := hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	// Set the server URL and use a low heartbeat timeout for quick test completion.
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	hive.RegisterFlags(flags)
	flags.Set(option.K8sAPIServer, srv.URL)
	flags.Set(option.K8sHeartbeatTimeout, "5ms")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	c.Assert(hive.Start(ctx), IsNil)

	// Check that we see the connection probe and version check
	c.Assert(getRequest("/api/v1/namespaces/kube-system"), NotNil)
	c.Assert(getRequest("/version"), NotNil)
	semVer := k8sversion.Version()
	c.Assert(semVer.Minor, Equals, uint64(99))

	// Wait until heartbeat has been seen to check that heartbeats are
	// running.
	err := testutils.WaitUntil(
		func() bool { return getRequest("/healthz") != nil },
		time.Second)
	c.Assert(err, IsNil)

	// Test that all different clientsets are wired correctly.
	_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(getRequest("/api/v1/namespaces/test/pods/pod"), NotNil)

	_, err = clientset.Slim().CoreV1().Pods("test").Get(context.TODO(), "slim-pod", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(getRequest("/api/v1/namespaces/test/pods/slim-pod"), NotNil)

	_, err = clientset.ExtensionsV1beta1().DaemonSets("test").Get(context.TODO(), "ds", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(getRequest("/apis/extensions/v1beta1/namespaces/test/daemonsets/ds"), NotNil)

	_, err = clientset.CiliumV2().CiliumEndpoints("test").Get(context.TODO(), "ces", metav1.GetOptions{})
	c.Assert(err, IsNil)
	c.Assert(getRequest("/apis/cilium.io/v2/namespaces/test/ciliumendpoints/ces"), NotNil)

	c.Assert(hive.Stop(ctx), IsNil)
}
