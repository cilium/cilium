// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func Test_runHeartbeat(t *testing.T) {
	// k8s api server never replied back in the expected time. We should close all connections
	k8smetrics.LastSuccessInteraction.Reset()
	time.Sleep(2 * time.Millisecond)

	testCtx, testCtxCancel := context.WithCancel(context.Background())

	called := make(chan struct{})
	runHeartbeat(
		hivetest.Logger(t),
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
	require.NoError(t, err, "Heartbeat should have closed all connections")
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
		hivetest.Logger(t),
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
	require.NoError(t, err, "Heartbeat should have closed all connections")
	testCtxCancel()

	// Cilium is successfully talking with kube-apiserver, we should not do
	// anything.
	k8smetrics.LastSuccessInteraction.Reset()

	called = make(chan struct{})
	runHeartbeat(
		hivetest.Logger(t),
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		10*time.Millisecond,
		func() {
			t.Error("This should not have been called!")
		},
	)

	select {
	case <-time.After(20 * time.Millisecond):
	case <-called:
		t.Error("Heartbeat should have closed all connections")
	}

	// Cilium had the last interaction with kube-apiserver a long time ago.
	// We should perform a heartbeat
	k8smetrics.LastInteraction.Reset()
	time.Sleep(50 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		hivetest.Logger(t),
		func(ctx context.Context) error {
			close(called)
			return nil
		},
		10*time.Millisecond,
		func() {
			t.Error("This should not have been called!")
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
	require.NoError(t, err, "Heartbeat should have closed all connections")

	// Cilium had the last interaction with kube-apiserver a long time ago.
	// We should perform a heartbeat but the heart beat will return
	// an error so we should close all connections
	k8smetrics.LastInteraction.Reset()
	time.Sleep(50 * time.Millisecond)

	called = make(chan struct{})
	runHeartbeat(
		hivetest.Logger(t),
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
	require.NoError(t, err, "Heartbeat should have closed all connections")
}

func Test_client(t *testing.T) {
	var requests lock.Map[string, *http.Request]
	getRequest := func(k string) *http.Request {
		v, _ := requests.Load(k)
		return v
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
	flags.Set(option.K8sAPIServerURLs, srv.URL)
	flags.Set(option.K8sHeartbeatTimeout, "150ms")
	// Set a higher QPS limit as the test exercises timing aspects.
	flags.Set(option.K8sClientQPSLimit, "500")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(t)
	require.NoError(t, hive.Start(tlog, ctx))

	// Check that we see the connection probe and version check
	require.NotNil(t, getRequest("/api/v1/namespaces/kube-system"))
	require.NotNil(t, getRequest("/version"))
	semVer := k8sversion.Version()
	require.Equal(t, uint64(99), semVer.Minor)

	// Wait until heartbeat has been seen to check that heartbeats are
	// running.
	err := testutils.WaitUntil(
		func() bool { return getRequest("/healthz") != nil },
		time.Second)
	require.NoError(t, err)

	// Test that all different clientsets are wired correctly.
	_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/pod"))

	_, err = clientset.Slim().CoreV1().Pods("test").Get(context.TODO(), "slim-pod", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/slim-pod"))

	_, err = clientset.ExtensionsV1beta1().DaemonSets("test").Get(context.TODO(), "ds", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/apis/extensions/v1beta1/namespaces/test/daemonsets/ds"))

	_, err = clientset.CiliumV2().CiliumEndpoints("test").Get(context.TODO(), "ces", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/apis/cilium.io/v2/namespaces/test/ciliumendpoints/ces"))

	require.NoError(t, hive.Stop(tlog, ctx))
}

func Test_clientMultipleAPIServers(t *testing.T) {
	var requests lock.Map[string, *http.Request]
	getRequest := func(k string) *http.Request {
		v, _ := requests.Load(k)
		return v
	}
	apiStateFile, err := os.CreateTemp("", "kubeapi_state")
	require.NoError(t, err)
	K8sAPIServerFilePath = apiStateFile.Name()

	servers := make([]*httptest.Server, 3)
	for i := range 3 {
		servers[i] = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}
	servers[0].Start()
	defer servers[0].Close()
	servers[1].Start()
	servers[2].Start()

	var clientset Clientset
	hive := hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	// Set the server URL and use a low heartbeat timeout for quick test completion.
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	hive.RegisterFlags(flags)
	urls := []string{servers[0].URL, servers[1].URL, servers[2].URL}
	flags.Set(option.K8sAPIServerURLs, strings.Join(urls, ","))
	flags.Set(option.K8sHeartbeatTimeout, "150ms")
	// Set a higher QPS limit as the test exercises timing aspects.
	flags.Set(option.K8sClientQPSLimit, "500")
	// 2/3 servers are stopped in order to validate that the agent connects to an active server.
	servers[1].Close()
	servers[2].Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(t)
	require.NoError(t, hive.Start(tlog, ctx))

	// Check that we see the connection probe and version check
	require.NotNil(t, getRequest("/api/v1/namespaces/kube-system"))
	require.NotNil(t, getRequest("/version"))
	semVer := k8sversion.Version()
	require.Equal(t, uint64(99), semVer.Minor)

	// Test that all different clientsets are wired correctly.
	_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/pod"))

	_, err = clientset.Slim().CoreV1().Pods("test").Get(context.TODO(), "slim-pod", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/slim-pod"))

	_, err = clientset.ExtensionsV1beta1().DaemonSets("test").Get(context.TODO(), "ds", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/apis/extensions/v1beta1/namespaces/test/daemonsets/ds"))

	_, err = clientset.CiliumV2().CiliumEndpoints("test").Get(context.TODO(), "ces", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/apis/cilium.io/v2/namespaces/test/ciliumendpoints/ces"))

	require.NoError(t, hive.Stop(tlog, ctx))
}

func Test_clientMultipleAPIServersServiceSwitchover(t *testing.T) {
	var requests lock.Map[string, *http.Request]
	getRequest := func(k string) *http.Request {
		v, _ := requests.Load(k)
		return v
	}
	apiStateFile, err := os.CreateTemp("", "kubeapi_state")
	require.NoError(t, err)
	defer apiStateFile.Close()
	K8sAPIServerFilePath = apiStateFile.Name()

	servers := make([]*httptest.Server, 3)
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}
	servers[0].Start()
	servers[1].Start()

	var clientset Clientset
	h := hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	urls := []string{servers[0].URL, servers[1].URL}
	flags.Set(option.K8sAPIServerURLs, strings.Join(urls, ","))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx))

	// Check that we see the connection probe and version check
	require.NotNil(t, getRequest("/api/v1/namespaces/kube-system"))
	require.NotNil(t, getRequest("/version"))
	semVer := k8sversion.Version()
	require.Equal(t, uint64(99), semVer.Minor)

	// Start server that responds to kube-api service address.
	servers[2].Start()
	defer servers[2].Close()
	mapping := K8sServiceEndpointMapping{
		Service: servers[2].URL,
	}
	UpdateK8sAPIServerEntry(tlog, mapping)
	// All servers are stopped in order to validate that the agent fails over correctly.
	servers[0].Close()
	servers[1].Close()

	require.NoError(t, testutils.WaitUntil(func() bool {
		_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})

		return err == nil
	}, 5*time.Second))
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/pod"))
	// Test that all different clientsets continue to have connectivity to kube-apiserver.

	_, err = clientset.Slim().CoreV1().Pods("test").Get(context.TODO(), "slim-pod", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/slim-pod"))

	_, err = clientset.ExtensionsV1beta1().DaemonSets("test").Get(context.TODO(), "ds", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/apis/extensions/v1beta1/namespaces/test/daemonsets/ds"))

	_, err = clientset.CiliumV2().CiliumEndpoints("test").Get(context.TODO(), "ces", metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, getRequest("/apis/cilium.io/v2/namespaces/test/ciliumendpoints/ces"))

	require.NoError(t, h.Stop(tlog, ctx))

	// Test the agent connects to the restored service address after restart.
	h = hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	flags = pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	flags.Set(option.K8sAPIServerURLs, strings.Join(urls, ","))
	ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog = hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx))

	require.NoError(t, testutils.WaitUntil(func() bool {
		_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})

		return err == nil
	}, 5*time.Second))
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/pod"))

	require.NoError(t, h.Stop(tlog, ctx))
}

func Test_clientMultipleAPIServersFailedRestore(t *testing.T) {
	var requests lock.Map[string, *http.Request]
	getRequest := func(k string) *http.Request {
		v, _ := requests.Load(k)
		return v
	}
	apiStateFile, err := os.CreateTemp("", "kubeapi_state")
	require.NoError(t, err)
	defer apiStateFile.Close()
	K8sAPIServerFilePath = apiStateFile.Name()

	servers := make([]*httptest.Server, 4)
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}
	servers[0].Start()
	servers[1].Start()

	var clientset Clientset
	h := hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	urls := []string{servers[0].URL, servers[1].URL}
	flags.Set(option.K8sAPIServerURLs, strings.Join(urls, ","))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx))

	// Check that we see the connection probe and version check
	require.NotNil(t, getRequest("/api/v1/namespaces/kube-system"))
	require.NotNil(t, getRequest("/version"))
	semVer := k8sversion.Version()
	require.Equal(t, uint64(99), semVer.Minor)

	// Write a bogus service address so that it won't be restored, and agent falls back
	// to user provided server URLs.
	mapping := K8sServiceEndpointMapping{
		Service: "http://10.10.10.10",
	}
	// Close previous servers, and start a new one.
	servers[0].Close()
	servers[1].Close()
	servers[2].Start()
	defer servers[2].Close()
	servers[3].Start()
	defer servers[3].Close()
	UpdateK8sAPIServerEntry(tlog, mapping)

	h = hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	flags = pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	// User provides a new server.
	urls = []string{servers[2].URL, servers[3].URL}
	flags.Set(option.K8sAPIServerURLs, strings.Join(urls, ","))
	// Set lower timeouts for tests.
	connRetryInterval = 5 * time.Millisecond
	connTimeout = 100 * time.Millisecond
	ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog = hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx))

	require.NoError(t, testutils.WaitUntil(func() bool {
		_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})

		return err == nil
	}, 5*time.Second))
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/pod"))

	require.NoError(t, h.Stop(tlog, ctx))
}

func Test_clientMultipleAPIServersFailedHeartbeat(t *testing.T) {
	var healthServer lock.Map[string, string]
	getServer := func(k string) string {
		v, _ := healthServer.Load(k)
		return v
	}
	var requests lock.Map[string, *http.Request]
	getRequest := func(k string) *http.Request {
		v, _ := requests.Load(k)
		return v
	}
	apiStateFile, err := os.CreateTemp("", "kubeapi_state")
	require.NoError(t, err)
	defer apiStateFile.Close()
	K8sAPIServerFilePath = apiStateFile.Name()

	servers := make([]*httptest.Server, 3)
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Store(r.URL.Path, r)

			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/version":
				w.Write([]byte(`{
			       "major": "1",
			       "minor": "99"
			}`))
			case "/healthz":
				healthServer.Store("health", "http://"+r.Host)
			default:
				w.Write([]byte("{}"))
			}
		}))
	}
	servers[0].Start()
	servers[1].Start()

	var clientset Clientset
	h := hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	urls := []string{servers[0].URL, servers[1].URL}
	flags.Set(option.K8sAPIServerURLs, strings.Join(urls, ","))
	flags.Set(option.K8sHeartbeatTimeout, "1s")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, ctx))

	// Check that we see the connection probe and version check
	require.NotNil(t, getRequest("/api/v1/namespaces/kube-system"))
	require.NotNil(t, getRequest("/version"))
	semVer := k8sversion.Version()
	require.Equal(t, uint64(99), semVer.Minor)

	// Fail the heartbeat to validate that API server URL is rotated.
	require.NoError(t, testutils.WaitUntil(func() bool {
		s := getServer("health")
		if s != "" {
			if servers[0].URL == s {
				// Close the current active server.
				servers[0].Close()
			} else {
				servers[1].Close()
			}
			return true
		}

		return false
	}, 5*time.Second))

	require.NoError(t, testutils.WaitUntil(func() bool {
		_, err := clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})

		return err == nil
	}, 5*time.Second))
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/pod"))

	// Validate manual URL rotation isn't triggered after switch to the service address.
	// Start server that responds to kube-apiserver address.
	servers[2].Start()
	defer servers[2].Close()
	servers[0].Close()
	servers[1].Close()
	mapping := K8sServiceEndpointMapping{
		Service: servers[2].URL,
		// Add bogus endpoints
		Endpoints: []string{"10.0.0.0:60"},
	}
	UpdateK8sAPIServerEntry(tlog, mapping)

	require.NoError(t, testutils.WaitUntil(func() bool {
		_, err = clientset.CoreV1().Pods("test").Get(context.TODO(), "pod", metav1.GetOptions{})

		return err == nil
	}, 5*time.Second))
	require.NotNil(t, getRequest("/api/v1/namespaces/test/pods/pod"))

	require.NoError(t, h.Stop(tlog, ctx))
}

func BenchmarkIsConnReady(b *testing.B) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	server.Start()
	defer server.Close()

	var clientset Clientset
	h := hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	flags.Set(option.K8sAPIServerURLs, server.URL)
	// Bump up the settings for concurrent requests.
	flags.Set(option.K8sClientBurst, "100")
	flags.Set(option.K8sClientQPSLimit, "100")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(b)
	require.NoError(b, h.Start(tlog, ctx))

	for b.Loop() {
		require.NoError(b, isConnReady(clientset))
	}

	require.NoError(b, h.Stop(tlog, ctx))
}

func BenchmarkIsConnReadyMultipleAPIServers(b *testing.B) {
	apiStateFile, err := os.CreateTemp("", "kubeapi_state")
	require.NoError(b, err)
	defer apiStateFile.Close()
	K8sAPIServerFilePath = apiStateFile.Name()

	servers := make([]*httptest.Server, 3)
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}
	servers[0].Start()
	servers[1].Start()
	servers[2].Start()

	var clientset Clientset
	h := hive.New(
		Cell,
		cell.Invoke(func(c Clientset) { clientset = c }),
	)

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	urls := []string{servers[0].URL, servers[1].URL, servers[2].URL}
	flags.Set(option.K8sAPIServerURLs, strings.Join(urls, ","))
	// Bump up the settings for concurrent requests.
	flags.Set(option.K8sClientBurst, "100")
	flags.Set(option.K8sClientQPSLimit, "100")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(b)
	require.NoError(b, h.Start(tlog, ctx))

	num := 20
	for b.Loop() {
		var wg sync.WaitGroup
		wg.Add(num)
		for range num {
			go func() {
				require.NoError(b, isConnReady(clientset))
				wg.Done()
			}()
		}
		wg.Wait()
	}

	require.NoError(b, h.Stop(tlog, ctx))
}
