// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/version"
)

type restConfigManager struct {
	restConfig    *rest.Config
	apiServerURLs []*url.URL
	lock.RWMutex
	log logrus.FieldLogger
	rt  *rotatingHttpRoundTripper
}

type restConfig interface {
	getConfig() *rest.Config
	canRotateAPIServerURL() bool
	rotateAPIServerURL()
}

func (r *restConfigManager) getConfig() *rest.Config {
	r.RLock()
	defer r.RUnlock()
	return rest.CopyConfig(r.restConfig)
}

func (r *restConfigManager) canRotateAPIServerURL() bool {
	return len(r.apiServerURLs) > 1
}

func restConfigManagerInit(cfg Config, name string, log logrus.FieldLogger) (restConfig, error) {
	var err error
	manager := restConfigManager{
		log: log,
		rt: &rotatingHttpRoundTripper{
			log: log,
		}}

	manager.parseConfig(cfg)

	cmdName := "cilium"
	if len(os.Args[0]) != 0 {
		cmdName = filepath.Base(os.Args[0])
	}
	userAgent := fmt.Sprintf("%s/%s", cmdName, version.Version)

	if name != "" {
		userAgent = fmt.Sprintf("%s %s", userAgent, name)
	}

	if manager.restConfig, err = manager.createConfig(cfg, userAgent); err != nil {
		return nil, err
	}
	if manager.canRotateAPIServerURL() {
		// Pick an API server at random.
		manager.rotateAPIServerURL()
	}

	return &manager, err
}

// createConfig creates a rest.Config for connecting to k8s api-server.
//
// The precedence of the configuration selection is the following:
// 1. kubeCfgPath
// 2. apiServerURL(s) (https if specified)
// 3. rest.InClusterConfig().
func (r *restConfigManager) createConfig(cfg Config, userAgent string) (*rest.Config, error) {
	var (
		config       *rest.Config
		err          error
		apiServerURL string
	)
	if cfg.K8sAPIServer != "" {
		apiServerURL = cfg.K8sAPIServer
	} else if len(r.apiServerURLs) > 0 {
		apiServerURL = r.apiServerURLs[0].String()
	}
	kubeCfgPath := cfg.K8sKubeConfigPath
	qps := cfg.K8sClientQPS
	burst := cfg.K8sClientBurst

	switch {
	// If the apiServerURL and the kubeCfgPath are empty then we can try getting
	// the rest.Config from the InClusterConfig
	case apiServerURL == "" && kubeCfgPath == "":
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
	case kubeCfgPath != "":
		if config, err = clientcmd.BuildConfigFromFlags("", kubeCfgPath); err != nil {
			return nil, err
		}
	case strings.HasPrefix(apiServerURL, "https://"):
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
		config.Host = apiServerURL
	default:
		//exhaustruct:ignore
		config = &rest.Config{Host: apiServerURL, UserAgent: userAgent}
	}

	// The HTTP round tripper rotates API server URLs in case of connectivity failures.
	if len(r.apiServerURLs) > 1 {
		config.Wrap(r.WrapRoundTripper)
	}

	setConfig(config, userAgent, qps, burst)
	return config, nil
}

func (r *restConfigManager) parseConfig(cfg Config) {
	if cfg.K8sAPIServer != "" {
		var (
			serverURL *url.URL
			err       error
		)
		s := cfg.K8sAPIServer
		if !strings.HasPrefix(s, "http") {
			s = fmt.Sprintf("http://%s", s) // default to HTTP
		}
		serverURL, err = url.Parse(s)
		if err != nil {
			r.log.WithError(err).Errorf("Failed to parse APIServerURL %s, skipping", serverURL)
			return
		}
		r.apiServerURLs = append(r.apiServerURLs, serverURL)
		return
	}
	for _, apiServerURL := range cfg.K8sAPIServerURLs {
		if apiServerURL == "" {
			continue
		}

		if !strings.HasPrefix(apiServerURL, "http") && !strings.HasPrefix(apiServerURL, "https") {
			apiServerURL = fmt.Sprintf("https://%s", apiServerURL)
		}

		serverURL, err := url.Parse(apiServerURL)
		if err != nil {
			r.log.WithError(err).Errorf("Failed to parse APIServerURL %s, skipping", apiServerURL)
			continue
		}

		r.apiServerURLs = append(r.apiServerURLs, serverURL)
	}
}

func setConfig(config *rest.Config, userAgent string, qps float32, burst int) {
	if userAgent != "" {
		config.UserAgent = userAgent
	}
	if qps != 0.0 {
		config.QPS = qps
	}
	if burst != 0 {
		config.Burst = burst
	}
}

func (r *restConfigManager) rotateAPIServerURL() {
	if len(r.apiServerURLs) <= 1 {
		return
	}

	r.rt.Lock()
	defer r.rt.Unlock()
	for {
		idx := rand.IntN(len(r.apiServerURLs))
		if r.rt.apiServerURL != r.apiServerURLs[idx] {
			r.rt.apiServerURL = r.apiServerURLs[idx]
			break
		}
	}
	r.Lock()
	r.restConfig.Host = r.rt.apiServerURL.String()
	r.Unlock()
	r.log.WithField("url", r.rt.apiServerURL).Info("Rotated api server")
}

// rotatingHttpRoundTripper sets the remote host in the rest configuration used to make API requests to the API server.
type rotatingHttpRoundTripper struct {
	delegate     http.RoundTripper
	log          logrus.FieldLogger
	apiServerURL *url.URL
	lock.RWMutex // Synchronizes access to apiServerURL
}

func (rt *rotatingHttpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.RLock()
	defer rt.RUnlock()

	rt.log.WithField("host", rt.apiServerURL).Debug("Kubernetes api server host")
	req.URL.Host = rt.apiServerURL.Host
	return rt.delegate.RoundTrip(req)
}

func (r *restConfigManager) WrapRoundTripper(rt http.RoundTripper) http.RoundTripper {
	r.rt.delegate = rt
	return r.rt
}
