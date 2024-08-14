// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/cilium/cilium/pkg/safeio"
)

const envoySocketDirPath = "/var/run/cilium/envoy/sockets/"

type envoyAdminClient struct {
	adminURL string
	unixPath string
}

func newEnvoyAdminClient() *envoyAdminClient {
	return &envoyAdminClient{
		// Needs to be provided to envoy (received as ':authority') - even though we Dial to a Unix domain socket.
		adminURL: fmt.Sprintf("http://%s/", "envoy-admin"),
		unixPath: filepath.Join(envoySocketDirPath, "admin.sock"),
	}
}

func (a *envoyAdminClient) get(path string) (string, error) {
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

	u, err := url.Parse(fmt.Sprintf("%s%s", a.adminURL, path))
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	resp, err := client.Get(u.String())
	if err != nil {
		return "", fmt.Errorf("failed to call %q endpoint: %w", path, err)
	}
	defer conn.Close()
	defer resp.Body.Close()

	body, err := safeio.ReadAllLimit(resp.Body, safeio.MB)
	if err != nil {
		return "", fmt.Errorf("failed to read %q response: %w", path, err)
	}

	return string(body), nil
}

func (a *envoyAdminClient) GetConfigDump(resourceType string, resourceName string) (string, error) {
	path := "config_dump?include_eds"

	if len(resourceType) > 0 {
		path = path + "&resource=" + resourceType
	}

	if len(resourceName) > 0 {
		path = path + "&name_regex=" + resourceName
	}

	return a.get(path)
}

func (a *envoyAdminClient) GetServerInfo() (string, error) {
	return a.get("server_info")
}

func (a *envoyAdminClient) GetPrometheusStatistics(filterRegex string) (string, error) {
	path := "stats/prometheus"

	if len(filterRegex) > 0 {
		path = path + "?filter=" + filterRegex
	}

	return a.get(path)
}
