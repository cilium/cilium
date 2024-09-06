// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/safeio"
)

type EnvoyAdminClient struct {
	adminURL        string
	unixPath        string
	currentLogLevel string
	defaultLogLevel string
}

func NewEnvoyAdminClientForSocket(envoySocketDir string, defaultLogLevel string) *EnvoyAdminClient {
	return &EnvoyAdminClient{
		// Needs to be provided to envoy (received as ':authority') - even though we Dial to a Unix domain socket.
		adminURL:        fmt.Sprintf("http://%s/", "envoy-admin"),
		unixPath:        getAdminSocketPath(envoySocketDir),
		defaultLogLevel: defaultLogLevel,
	}
}

func (a *EnvoyAdminClient) transact(query string) error {
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
		return err
	}
	defer conn.Close()
	defer resp.Body.Close()
	body, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return err
	}
	ret := strings.ReplaceAll(string(body), "\r", "")
	log.Debugf("Envoy: Admin response to %s: %s", query, ret)
	return nil
}

// ChangeLogLevel changes Envoy log level to correspond to the logrus log level 'level'.
func (a *EnvoyAdminClient) ChangeLogLevel(agentLogLevel logrus.Level) error {
	envoyLevel := mapLogLevel(agentLogLevel, a.defaultLogLevel)

	if envoyLevel == a.currentLogLevel {
		log.Debugf("Envoy: Log level is already set as: %v", envoyLevel)
		return nil
	}

	err := a.transact("logging?level=" + envoyLevel)
	if err != nil {
		log.WithError(err).Warnf("Envoy: Failed to set log level to: %v", envoyLevel)
	} else {
		a.currentLogLevel = envoyLevel
	}
	return err
}

func (a *EnvoyAdminClient) quit() error {
	return a.transact("quitquitquit")
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

	serverInfo := map[string]interface{}{}
	if err := json.Unmarshal(body, &serverInfo); err != nil {
		return "", fmt.Errorf("failed to parse ServerInfo: %w", err)
	}

	version, ok := serverInfo["version"]

	if !ok {
		return "", errors.New("failed to read version from ServerInfo")
	}

	return fmt.Sprintf("%s", version), nil
}
