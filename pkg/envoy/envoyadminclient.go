// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/safeio"
)

type EnvoyAdminClient struct {
	logger          *slog.Logger
	adminURL        string
	unixPath        string
	currentLogLevel string
	defaultLogLevel string
}

func NewEnvoyAdminClientForSocket(logger *slog.Logger, envoySocketDir string, defaultLogLevel string) *EnvoyAdminClient {
	return &EnvoyAdminClient{
		logger: logger,

		// Needs to be provided to envoy (received as ':authority') - even though we Dial to a Unix domain socket.
		adminURL:        fmt.Sprintf("http://%s/", "envoy-admin"),
		unixPath:        getAdminSocketPath(envoySocketDir),
		defaultLogLevel: defaultLogLevel,
	}
}

// Post sends a POST request with the given query to the Envoy Admin API.
func (a *EnvoyAdminClient) Post(query string) (string, error) {
	// Use a custom dialer to use a Unix domain socket for an HTTP connection.
	var conn net.Conn
	var err error
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				conn, err = net.Dial("unix", a.unixPath)
				return conn, err
			},
		},
	}

	resp, err := client.Post(a.adminURL+query, "", nil)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	defer resp.Body.Close()
	body, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return "", err
	}

	ret := strings.ReplaceAll(string(body), "\r", "")
	a.logger.Debug("Envoy: Admin response",
		logfields.Request, query,
		logfields.Response, ret,
	)

	return string(body), nil
}

// ChangeLogLevel changes Envoy log level to correspond to the logrus log level 'level'.
func (a *EnvoyAdminClient) ChangeLogLevel(agentLogLevel slog.Level) error {
	envoyLevel := mapLogLevel(agentLogLevel, a.defaultLogLevel)

	if envoyLevel == a.currentLogLevel {
		a.logger.Debug("Envoy: Log level is already set",
			logfields.Value, envoyLevel,
		)
		return nil
	}

	if _, err := a.Post("logging?level=" + envoyLevel); err != nil {
		a.logger.Warn("Envoy: Failed to set log level",
			logfields.Value, envoyLevel,
			logfields.Error, err,
		)
		return err
	}

	a.currentLogLevel = envoyLevel
	return nil
}

func (a *EnvoyAdminClient) quit() error {
	_, err := a.Post("quitquitquit")
	return err
}

// GetEnvoyVersion returns the envoy binary version string
func (a *EnvoyAdminClient) GetEnvoyVersion() (string, error) {
	// Use a custom dialer to use a Unix domain socket for a HTTP connection.
	var conn net.Conn
	var err error
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				conn, err = net.Dial("unix", a.unixPath)
				return conn, err
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("%s%s", a.adminURL, "server_info"))
	if err != nil {
		return "", fmt.Errorf("failed to call ServerInfo endpoint: %w", err)
	}
	defer conn.Close()
	defer resp.Body.Close()

	body, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return "", fmt.Errorf("failed to read ServerInfo response: %w", err)
	}

	serverInfo := map[string]any{}
	if err := json.Unmarshal(body, &serverInfo); err != nil {
		return "", fmt.Errorf("failed to parse ServerInfo: %w", err)
	}

	version, ok := serverInfo["version"]

	if !ok {
		return "", errors.New("failed to read version from ServerInfo")
	}

	return fmt.Sprintf("%s", version), nil
}
