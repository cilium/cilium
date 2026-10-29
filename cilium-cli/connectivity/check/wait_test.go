// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type execProbeRoundTripper func(*http.Request) (*http.Response, error)

func (f execProbeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestWaitForExecProbesBoundsStalledRequests(t *testing.T) {
	service := Service{Service: &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo"},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.0.1",
			Ports:     []corev1.ServicePort{{NodePort: 30080}},
		},
	}}
	for _, tt := range []struct {
		name string
		wait func(context.Context, Logger, Pod) error
	}{
		{"pod DNS", func(ctx context.Context, log Logger, pod Pod) error {
			return WaitForPodDNS(ctx, log, pod, pod)
		}},
		{"CoreDNS", WaitForCoreDNS},
		{"Service DNS", func(ctx context.Context, log Logger, pod Pod) error {
			return WaitForService(ctx, log, pod, service)
		}},
		{"Service endpoints", func(ctx context.Context, log Logger, pod Pod) error {
			return WaitForServiceEndpoints(ctx, log, pod, service, 1, []features.IPFamily{features.IPFamilyV4})
		}},
		{"NodePort", func(ctx context.Context, log Logger, pod Pod) error {
			return WaitForNodePorts(ctx, log, pod, "192.0.2.1", service)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				go func() {
					time.Sleep(time.Minute)
					close(release)
				}()

				var requests atomic.Int32
				config := &rest.Config{
					Host: "https://apiserver.invalid",
					WrapTransport: func(http.RoundTripper) http.RoundTripper {
						return execProbeRoundTripper(func(*http.Request) (*http.Response, error) {
							requests.Add(1)
							// Model an exec upgrade that ignores context cancellation.
							<-release
							return nil, context.DeadlineExceeded
						})
					},
				}
				clientset, err := kubernetes.NewForConfig(config)
				require.NoError(t, err)
				pod := Pod{
					K8sClient: &k8s.Client{Clientset: clientset, Config: config},
					Pod: &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{Namespace: "cilium-test", Name: "client"},
						Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "client"}}},
						Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "192.0.2.2"}}},
					},
				}
				log := &ConnectivityTest{params: Parameters{Writer: &bytes.Buffer{}}}
				ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
				defer cancel()

				start := time.Now()
				err = tt.wait(ctx, log, pod)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Equal(t, 40*time.Second, time.Since(start))
				assert.GreaterOrEqual(t, requests.Load(), int32(2))
				<-release
				synctest.Wait()
			})
		})
	}
}

func TestPollExecProbeTimeoutBudget(t *testing.T) {
	for _, tt := range []struct {
		name     string
		err      error
		attempts int
	}{
		{"exec attempt timeout", fmt.Errorf("exec timed out: %w", context.DeadlineExceeded), 2},
		{"probe not ready", errors.New("DNS not ready"), 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				attempts := 0
				err := pollExecProbe(t.Context(), time.Second, func() error {
					attempts++
					if attempts == 1 {
						time.Sleep(2 * time.Second)
						return tt.err
					}
					return nil
				})
				if tt.attempts == 2 {
					assert.NoError(t, err)
				} else {
					assert.ErrorIs(t, err, tt.err)
				}
				assert.Equal(t, tt.attempts, attempts)
			})
		})
	}
}
