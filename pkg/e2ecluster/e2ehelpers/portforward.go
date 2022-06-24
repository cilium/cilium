// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package e2ehelpers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// PortForwardPod forwards one or more ports to a given pod. Port forwards are
// automatically cleaned up when the test exits. Ports should be specified in the form
// "src:dst" where "src" and "dst" are port numbers.
//
// out and outErr are pointers to os.File that should be used by the portforwarder for its
// stdout and stderr respectively. These can be set to nil to ignore output.
//
// retries and retryBackoff can be used to configure how many times this function should
// retry on failure to set up the port forward and how long it should wait between retries.
func PortForwardPod(testenv env.Environment, pod *corev1.Pod, out, outErr *os.File, retries uint, retryBackoff time.Duration, ports ...string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		restCfg, err := getRestConfig(cfg)
		if err != nil {
			return ctx, err
		}

		restClient, err := rest.RESTClientFor(restCfg)
		if err != nil {
			return ctx, err
		}

		reqUrl := restClient.Post().
			Resource("pods").
			Name(pod.Name).
			Namespace(pod.Namespace).
			SubResource("portforward").
			URL()

		stopChan := make(chan struct{})
		readyChan := make(chan struct{})

		var pfwd *portforward.PortForwarder
		for i := uint(0); ; i++ {
			pfwd, err = newPortForwarder(restCfg, reqUrl, out, outErr, stopChan, readyChan, ports)
			if err == nil || i == retries {
				break
			}
			time.Sleep(retryBackoff)
			klog.V(2).InfoS("Failed to port forward, retrying",
				"pod", pod.Name,
				"namespace", pod.Namespace,
				"ports", ports,
				"attempt", i,
				"err", err)
		}
		if err != nil {
			return ctx, fmt.Errorf("failed to portforward after %d retries: %w", retries, err)
		}

		// Automatically stop portforwarding
		testenv.Finish(func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			klog.V(2).InfoS("Test ended, stopping portforward",
				"pod", pod.Name,
				"namespace", pod.Namespace,
				"ports", ports)
			close(stopChan)
			return ctx, nil
		})

		klog.V(2).InfoS("Starting portforward",
			"pod", pod.Name,
			"namespace", pod.Namespace,
			"ports", ports)

		go func() {
			if err := pfwd.ForwardPorts(); err != nil {
				klog.ErrorS(fmt.Errorf("error during portforward: %w", err),
					"pod", pod.Name,
					"namespace", pod.Namespace,
					"ports", ports)
			}
		}()

		return ctx, nil
	}
}

func newPortForwarder(restCfg *rest.Config, reqUrl *url.URL, out, outErr *os.File, stopChan, readyChan chan struct{}, ports []string) (*portforward.PortForwarder, error) {
	transport, upgrader, err := spdy.RoundTripperFor(restCfg)
	if err != nil {
		return nil, err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, reqUrl)

	return portforward.New(dialer, ports, stopChan, readyChan, out, outErr)
}

func getRestConfig(cfg *envconf.Config) (*rest.Config, error) {
	client, err := cfg.NewClient()
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("error adding to scheme: %w", err)
	}

	restCfg := *client.RESTConfig()
	restCfg.GroupVersion = &schema.GroupVersion{
		Group:   "api",
		Version: "v1",
	}
	restCfg.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{
		CodecFactory: serializer.NewCodecFactory(scheme),
	}

	return &restCfg, nil
}
