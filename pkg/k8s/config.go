// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package k8s abstracts all Kubernetes specific behaviour
package k8s

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// config is the configuration of Kubernetes related settings
	config configuration
)

type configuration struct {
	// APIServerURL is the URL address of the API server
	APIServerURL *url.URL

	// APIServerURLs is the list of addresses for the API server instances
	APIServerURLs []*url.URL

	// KubeconfigPath is the local path to the kubeconfig configuration
	// file on the filesystem
	KubeconfigPath string

	// QPS is the QPS to pass to the kubernetes client configuration.
	QPS float32

	// Burst is the burst to pass to the kubernetes client configuration.
	Burst int

	lock.RWMutex
}

// GetAPIServerURL returns the configured API server URL address.
func GetAPIServerURL() *url.URL {
	config.RLock()
	defer config.RUnlock()

	return config.APIServerURL
}

// GetAPIServerURLString returns the string representation of configured API server
// address.
func GetAPIServerURLString() string {
	config.RLock()
	defer config.RUnlock()

	if config.APIServerURL == nil {
		return ""
	}
	return config.APIServerURL.String()
}

// RotateAPIServerURL rotates the kubernetes API server URL used for clients.
// This is used when the currently registered kubernetes API server instance
// is not responding (failing heartbeat check).
func RotateAPIServerURL() {
	config.Lock()
	defer config.Unlock()

	if len(config.APIServerURLs) < 2 {
		return
	}

	log.WithField("oldURL", config.APIServerURL.String()).Info("Rotating API server URL")
	rand.Shuffle(len(config.APIServerURLs), func(i, j int) {
		config.APIServerURLs[i], config.APIServerURLs[j] = config.APIServerURLs[j], config.APIServerURLs[i]
	})

	for _, apiServerURL := range config.APIServerURLs {
		if apiServerURL.String() != config.APIServerURL.String() {
			log.WithField("url", apiServerURL.String()).Info("Using new API server URL")
			config.APIServerURL = apiServerURL
			break
		}
	}
}

// GetKubeconfigPath returns the configured path to the kubeconfig
// configuration file
func GetKubeconfigPath() string {
	return config.KubeconfigPath
}

// GetQPS gets the QPS of the K8s configuration.
func GetQPS() float32 {
	return config.QPS
}

// GetBurst gets the burst limit of the K8s configuration.
func GetBurst() int {
	return config.Burst
}

// Configure sets the parameters of the Kubernetes package
func Configure(apiServerURLs []string, kubeconfigPath string, qps float32, burst int) {
	config.APIServerURL = nil
	config.APIServerURLs = []*url.URL{}

	for _, apiServerURL := range apiServerURLs {
		if len(apiServerURL) == 0 {
			// Simply skip empty URLs in the list
			continue
		}

		// Default to HTTP scheme for server address.
		if !strings.HasPrefix(apiServerURL, "http") {
			apiServerURL = fmt.Sprintf("http://%s", apiServerURL)
		}

		parsedUrl, err := url.ParseRequestURI(apiServerURL)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse APIServer URL %s, skipping", apiServerURL)
			continue
		}

		if config.APIServerURL == nil {
			config.APIServerURL = parsedUrl
		} else {
			// All the APIServer URLs should have the same schemes
			// This is because we set up the client only once and then
			// modify the host using http.RoundTripper
			parsedUrl.Scheme = config.APIServerURL.Scheme
		}

		config.APIServerURLs = append(config.APIServerURLs, parsedUrl)
	}

	config.KubeconfigPath = kubeconfigPath
	config.QPS = qps
	config.Burst = burst
}

// IsEnabled checks if Cilium is being used in tandem with Kubernetes.
func IsEnabled() bool {
	if option.Config.DatapathMode == datapathOption.DatapathModeLBOnly {
		return false
	}

	return config.APIServerURL != nil ||
		config.KubeconfigPath != "" ||
		(os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
			os.Getenv("KUBERNETES_SERVICE_PORT") != "") ||
		os.Getenv("K8S_NODE_NAME") != ""
}

type httpRoundTripper struct {
	delegate http.RoundTripper
}

func (rt *httpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = GetAPIServerURL().Host
	return rt.delegate.RoundTrip(req)
}

func defaultHTTPRoundTripper(rt http.RoundTripper) http.RoundTripper {
	return &httpRoundTripper{
		delegate: rt,
	}
}
