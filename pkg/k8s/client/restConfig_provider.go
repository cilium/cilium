// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/cilium/pkg/version"
)

type restConfigManager struct {
	restConfig *rest.Config
	log        logrus.FieldLogger
}

type restConfig interface {
	getConfig() *rest.Config
}

func (r *restConfigManager) getConfig() *rest.Config {
	return rest.CopyConfig(r.restConfig)
}

func restConfigManagerInit(cfg Config, name string, log logrus.FieldLogger) (restConfig, error) {
	var err error
	manager := restConfigManager{log: log}

	cmdName := "cilium"
	if len(os.Args[0]) != 0 {
		cmdName = filepath.Base(os.Args[0])
	}
	userAgent := fmt.Sprintf("%s/%s", cmdName, version.Version)

	if name != "" {
		userAgent = fmt.Sprintf("%s %s", userAgent, name)
	}

	manager.restConfig, err = createConfig(cfg.K8sAPIServer, cfg.K8sKubeConfigPath, cfg.K8sClientQPS, cfg.K8sClientBurst, userAgent)

	return &manager, err
}

// createConfig creates a rest.Config for connecting to k8s api-server.
//
// The precedence of the configuration selection is the following:
// 1. kubeCfgPath
// 2. apiServerURL (https if specified)
// 3. rest.InClusterConfig().
func createConfig(apiServerURL, kubeCfgPath string, qps float32, burst int, userAgent string) (*rest.Config, error) {
	var (
		config *rest.Config
		err    error
	)

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

	setConfig(config, userAgent, qps, burst)
	return config, nil
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
