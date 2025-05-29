// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type envoyVersionChecker struct {
	logger        *slog.Logger
	externalEnvoy bool
	adminClient   *EnvoyAdminClient
}

// requiredEnvoyVersionSHA is set during build
// Running Envoy version will be checked against `requiredEnvoyVersionSHA`.
// By default, cilium-agent will fail to start if there is a version mismatch.
var requiredEnvoyVersionSHA string

func (r *envoyVersionChecker) checkEnvoyVersion() error {
	envoyVersion, err := r.getEnvoyVersion()
	if err != nil {
		return fmt.Errorf("failed to retrieve Envoy version: %w", err)
	}

	// Make sure Envoy version matches the required one
	if !strings.HasPrefix(envoyVersion, requiredEnvoyVersionSHA) {
		return fmt.Errorf("envoy version %s does not match with required version %s", envoyVersion, requiredEnvoyVersionSHA)
	}

	r.logger.Debug("Envoy: Envoy version is matching required version",
		logfields.Version, envoyVersion,
		logfields.Expected, requiredEnvoyVersionSHA,
	)

	return nil
}

func (r *envoyVersionChecker) getEnvoyVersion() (string, error) {
	if r.externalEnvoy {
		return r.getRemoteEnvoyVersion()
	} else {
		return getEmbeddedEnvoyVersion()
	}
}

func (r *envoyVersionChecker) getRemoteEnvoyVersion() (string, error) {
	const versionRetryAttempts = 20
	const versionRetryWait = 500 * time.Millisecond

	// Retry is necessary because Envoy might not be ready yet
	for i := 0; i <= versionRetryAttempts; i++ {
		envoyVersion, err := r.adminClient.GetEnvoyVersion()
		if err != nil {
			if i < versionRetryAttempts {
				r.logger.Info("Envoy: Unable to retrieve Envoy version - retry")
				time.Sleep(versionRetryWait)
				continue
			}
			return "", fmt.Errorf("failed to retrieve Envoy version: %w", err)
		}

		return envoyVersion, nil
	}

	return "", errors.New("failed to retrieve Envoy version")
}
