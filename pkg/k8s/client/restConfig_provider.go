// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/cilium/pkg/fswatcher"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s-client")

	// K8sAPIServerFilePath is the file path for storing kube-apiserver service and
	// endpoints for high availability failover.
	K8sAPIServerFilePath = filepath.Join(option.Config.StateDir, "k8sapi_server_state.json")
)

type K8sServiceEndpointMapping struct {
	Service   string   `json:"service"`
	Endpoints []string `json:"endpoints"`
}

// restConfigManager manages the rest configuration for connecting to the API server, including the logic to fail over
// to an active kube-apiserver in order to support high availability.
//
// Below are the sequence of events to support kube-apiserver failover.
//
// Bootstrap: It parses the user provided configuration which may include multiple API server URLs. In case of multiple
// API servers, it wraps the rest configuration with an HTTP RoundTripper that enables updating the remote host while
// making API requests to the kube-apiserver. It also asynchronously monitors kube-apiserver service and endpoints related updates.
// Initially an active kube-apiserver URL is picked at random, and servers are manually rotated on connectivity failures.
//
// Runtime: After the agent's initial sync with the kube-apiserver, when the manager receives updates for the kube-apiserver
// service, it switches over to the service address as the remote host set in the rest configuration. Thereafter, manual
// rotation of API servers is not needed as Cilium datapath will load-balance API traffic to the kube-apiserver endpoints.
//
// Restore: The manager restores the persisted kube-apiserver state after restart after ensuring connectivity using
// the service address. If that fails, it'll fall back to user provided kube-apiserver URLs. Note that these could be
// different from the ones configured during initial bootstrap as those kube-apiservers may all have been rotated while
// the agent was down.
type restConfigManager struct {
	restConfig    *rest.Config
	apiServerURLs []*url.URL
	lock.RWMutex
	log  logrus.FieldLogger
	rt   *rotatingHttpRoundTripper
	jobs job.Group
}

type restConfig interface {
	getConfig() *rest.Config
	canRotateAPIServerURL() bool
	rotateAPIServerURL()
}

// UpdateK8sAPIServerEntry writes the provided kubernetes service to endpoint mapping
// to K8sAPIServerFilePath.
func UpdateK8sAPIServerEntry(mapping K8sServiceEndpointMapping) {
	f, err := os.OpenFile(K8sAPIServerFilePath, os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	if err = json.NewEncoder(f).Encode(mapping); err != nil {
		log.WithError(err).WithField("entry", mapping).Error("failed to write kubernetes service entry," +
			"agent may not be able to fail over to an active k8sapi-server")
	}
}

func (r *restConfigManager) getConfig() *rest.Config {
	r.RLock()
	defer r.RUnlock()
	return rest.CopyConfig(r.restConfig)
}

func (r *restConfigManager) canRotateAPIServerURL() bool {
	r.RLock()
	defer r.RUnlock()
	return len(r.apiServerURLs) > 1
}

func restConfigManagerInit(cfg Config, name string, log logrus.FieldLogger, jobs job.Group) (restConfig, error) {
	var err error
	manager := restConfigManager{
		log: log,
		rt: &rotatingHttpRoundTripper{
			log: log,
		},
		jobs: jobs}

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
		if err := manager.startK8sAPIServerFileWatcher(); err != nil {
			return nil, fmt.Errorf("agent may not able to fail over to an active kube-apiserver: %w", err)
		}
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

// startK8sAPIServerFileWatcher asynchronosuly handles updates the API service and endpoints.
func (r *restConfigManager) startK8sAPIServerFileWatcher() error {
	if finfo, err := os.Stat(K8sAPIServerFilePath); errors.Is(err, os.ErrNotExist) {
		if _, err = os.Create(K8sAPIServerFilePath); err != nil {
			return fmt.Errorf("unable to create '%s': %w", K8sAPIServerFilePath, err)
		}
	} else if finfo.Size() != 0 {
		// Restore the service and endpoint addresses.
		r.updateK8sAPIServerURL()
	}

	r.jobs.Add(job.OneShot("kube-apiserver-state-file-watcher", func(ctx context.Context, health cell.Health) error {
		stop := make(chan struct{})
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		var (
			watcher *fswatcher.Watcher
			err     error
		)
		wait.Until(func() {
			watcher, err = fswatcher.New([]string{K8sAPIServerFilePath})
			if err == nil {
				close(stop)
				return
			}
			select {
			case <-ctx.Done():
			case <-timeout.C:
			default:
				return
			}
			close(stop)
		}, time.Second, stop)
		if err == nil {
			health.OK("Starting kube-apiserver state file watcher")
			return r.k8sAPIServerFileWatcher(ctx, watcher, health)
		}
		return fmt.Errorf("unable to add file watcher '%s': %w", K8sAPIServerFilePath, err)
	}))

	return nil
}

func (r *restConfigManager) k8sAPIServerFileWatcher(ctx context.Context, watcher *fswatcher.Watcher, health cell.Health) error {
	for {
		select {
		case <-ctx.Done():
			health.Stopped("Context done")
			watcher.Close()
			return nil
		case event := <-watcher.Events:
			if !event.Op.Has(fsnotify.Write) {
				continue
			}
			r.log.WithField("file", K8sAPIServerFilePath).Info("Processing write event ")
			r.updateK8sAPIServerURL()
		case err := <-watcher.Errors:
			health.Degraded(fmt.Sprintf("Failed to load  %q", K8sAPIServerFilePath), err)
			r.log.WithField("file", K8sAPIServerFilePath).WithError(err).Error("Unexpected error while watching")
		}

	}
}

func (r *restConfigManager) updateK8sAPIServerURL() {
	f, err := os.Open(K8sAPIServerFilePath)
	if err != nil {
		r.log.WithError(err).WithField(logfields.Path, K8sAPIServerFilePath).Error("unable " +
			"to open file, agent may not be able to fail over to an active kube-apiserver")
	}
	defer f.Close()

	var mapping K8sServiceEndpointMapping
	if err = json.NewDecoder(f).Decode(&mapping); err != nil {
		r.log.WithError(err).WithFields(logrus.Fields{
			logfields.Path: K8sAPIServerFilePath,
			"entry":        mapping,
		}).Error("failed to " +
			"decode file entry, agent may not be able to fail over to an active kube-apiserver")
	}
	if err = r.checkConnToService(mapping.Service); err != nil {
		return
	}
	r.log.WithField("host", mapping.Service).Info("Updated kubeapi server url host")
	// Set in tests
	mapping.Service = strings.TrimPrefix(mapping.Service, "http://")
	r.rt.Lock()
	defer r.rt.Unlock()
	r.rt.apiServerURL.Host = mapping.Service
	r.Lock()
	defer r.Unlock()
	r.restConfig.Host = mapping.Service
	updatedServerURLs := make([]*url.URL, 0)
	for _, endpoint := range mapping.Endpoints {
		endpoint = fmt.Sprintf("https://%s", endpoint)
		serverURL, err := url.Parse(endpoint)
		if err != nil {
			r.log.WithError(err).Errorf("Failed to parse endpoint %s, skipping", endpoint)
			continue
		}
		updatedServerURLs = append(updatedServerURLs, serverURL)
	}
	if len(updatedServerURLs) != 0 {
		r.apiServerURLs = updatedServerURLs
	}
}

// checkConnToService ensures connectivity to the API server via the passed service address.
func (r *restConfigManager) checkConnToService(host string) error {
	stop := make(chan struct{})
	timeout := time.NewTimer(connTimeout)
	defer timeout.Stop()
	var (
		config *rest.Config
		err    error
	)
	if strings.HasPrefix(host, "http") {
		// Set in tests
		//exhaustruct:ignore
		config = &rest.Config{Host: host, Timeout: connTimeout}
	} else {
		hostURL := fmt.Sprintf("https://%s", host)
		config, err = rest.InClusterConfig()
		if err != nil {
			log.WithError(err).Error("unable to read cluster config")
			return err
		}
		config.Host = hostURL
	}
	wait.Until(func() {
		r.log.WithField(logfields.Address, config.Host).Info("Checking connection to kubeapi service")
		httpClient, _ := rest.HTTPClientFor(config)

		cs, _ := kubernetes.NewForConfigAndClient(config, httpClient)
		if err = isConnReady(cs); err == nil {
			close(stop)
			return
		}

		select {
		case <-timeout.C:
		default:
			return
		}

		r.log.WithError(err).WithField(logfields.Address, config.Host).Error("kubeapi service not ready yet")
		close(stop)
	}, connRetryInterval, stop)
	if err == nil {
		r.log.WithField(logfields.Address, config.Host).Info("Connected to kubeapi service")
	}
	return err
}
