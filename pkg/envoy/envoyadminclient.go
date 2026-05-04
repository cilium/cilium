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
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/time"
)

const listenerDrainPollInterval = 100 * time.Millisecond

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

func (a *EnvoyAdminClient) do(method, query string) (string, error) {
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

	req, err := http.NewRequestWithContext(context.Background(), method, a.adminURL+query, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
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

// Get sends a GET request with the given query to the Envoy Admin API.
func (a *EnvoyAdminClient) Get(query string) (string, error) {
	return a.do(http.MethodGet, query)
}

// Post sends a POST request with the given query to the Envoy Admin API.
func (a *EnvoyAdminClient) Post(query string) (string, error) {
	return a.do(http.MethodPost, query)
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

// WaitForListenerDrain waits until the named listener disappears from Envoy's listener list,
// which indicates that the listener has fully drained and been removed.
func (a *EnvoyAdminClient) WaitForListenerDrain(listenerName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		body, err := a.Get("listeners?format=json")
		if err != nil {
			return fmt.Errorf("failed to query listener state for %q: %w", listenerName, err)
		}

		active, err := listenerPresent(body, listenerName)
		if err != nil {
			return fmt.Errorf("failed to parse listener state for %q: %w", listenerName, err)
		}
		if !active {
			return nil
		}

		if time.Now().After(deadline) {
			activeDownstream, err := a.getListenerDownstreamCxActive(listenerName)
			if err != nil {
				return fmt.Errorf("timed out waiting for listener %q to drain", listenerName)
			}
			return fmt.Errorf("timed out waiting for listener %q to drain: %d downstream connections still active", listenerName, activeDownstream)
		}

		time.Sleep(listenerDrainPollInterval)
	}
}

// listenerPresent reports whether the named listener exists in Envoy's JSON
// listener response.
func listenerPresent(body string, listenerName string) (bool, error) {
	var payload any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return false, err
	}
	return containsListenerName(payload, listenerName), nil
}

// containsListenerName recursively searches a decoded Envoy admin payload for a
// matching listener name.
func containsListenerName(v any, listenerName string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if k == "name" {
				if name, ok := child.(string); ok && name == listenerName {
					return true
				}
			}
			if containsListenerName(child, listenerName) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if containsListenerName(child, listenerName) {
				return true
			}
		}
	}
	return false
}

func (a *EnvoyAdminClient) getListenerDownstreamCxActive(listenerName string) (int, error) {
	filter := "^listener\\." + regexp.QuoteMeta(listenerName) + "\\.downstream_cx_active$"
	body, err := a.Get("stats?usedonly&filter=" + url.QueryEscape(filter))
	if err != nil {
		return 0, err
	}

	total := 0
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		_, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, fmt.Errorf("failed to parse downstream connection count %q: %w", line, err)
		}
		total += n
	}

	return total, nil
}
