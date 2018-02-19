// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	clientapi "github.com/cilium/cilium/api/v1/health/client"
	"github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/health/defaults"

	runtime_client "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// Client is a client for cilium health
type Client struct {
	clientapi.CiliumHealth
}

func configureTransport(tr *http.Transport, proto, addr string) *http.Transport {
	if tr == nil {
		tr = &http.Transport{}
	}

	if proto == "unix" {
		// No need for compression in local communications.
		tr.DisableCompression = true
		tr.Dial = func(_, _ string) (net.Conn, error) {
			return net.Dial(proto, addr)
		}
	} else {
		tr.Proxy = http.ProxyFromEnvironment
		tr.Dial = (&net.Dialer{}).Dial
	}

	return tr
}

// NewDefaultClient creates a client with default parameters connecting to UNIX domain socket.
func NewDefaultClient() (*Client, error) {
	return NewClient("")
}

// NewClient creates a client for the given `host`.
func NewClient(host string) (*Client, error) {
	if host == "" {
		// Check if environment variable points to socket
		e := os.Getenv(defaults.SockPathEnv)
		if e == "" {
			// If unset, fall back to default value
			e = defaults.SockPath
		}
		host = "unix://" + e
	}
	tmp := strings.SplitN(host, "://", 2)
	if len(tmp) != 2 {
		return nil, fmt.Errorf("invalid host format '%s'", host)
	}

	switch tmp[0] {
	case "tcp":
		if _, err := url.Parse("tcp://" + tmp[1]); err != nil {
			return nil, err
		}
		host = "http://" + tmp[1]
	case "unix":
		host = tmp[1]
	}

	transport := configureTransport(nil, tmp[0], host)
	httpClient := &http.Client{Transport: transport}
	clientTrans := runtime_client.NewWithClient(tmp[1], clientapi.DefaultBasePath,
		clientapi.DefaultSchemes, httpClient)
	return &Client{*clientapi.New(clientTrans, strfmt.Default)}, nil
}

// Hint tries to improve the error message displayed to the user.
func Hint(err error) error {
	if err == nil {
		return err
	}
	e, _ := url.PathUnescape(err.Error())
	if strings.Contains(err.Error(), defaults.SockPath) {
		return fmt.Errorf("%s\nIs the agent running?", e)
	}
	return fmt.Errorf("%s", e)
}

func connectivityStatusHealthy(cs *models.ConnectivityStatus) bool {
	return cs != nil && cs.Status == ""
}

func formatConnectivityStatus(w io.Writer, cs *models.ConnectivityStatus, path, indent string) {
	status := cs.Status
	if connectivityStatusHealthy(cs) {
		latency := time.Duration(cs.Latency)
		status = fmt.Sprintf("OK, RTT=%s", latency)
	}
	fmt.Fprintf(w, "%s%s:\t%s\n", indent, path, status)
}

func formatPathStatus(w io.Writer, name string, cp *models.PathStatus, indent string, verbose bool) {
	if cp == nil {
		if verbose {
			fmt.Fprintf(w, "%s%s connectivity:\tnil\n", indent, name)
		}
		return
	}
	fmt.Fprintf(w, "%s%s connectivity to %s:\n", indent, name, cp.IP)
	indent = fmt.Sprintf("%s  ", indent)

	statuses := map[string]*models.ConnectivityStatus{
		"ICMP":        cp.Icmp,
		"HTTP via L3": cp.HTTP,
	}
	for name, status := range statuses {
		if status != nil {
			formatConnectivityStatus(w, status, name, indent)
		}
	}
}

func pathIsHealthy(cp *models.PathStatus) bool {
	if cp == nil {
		return false
	}

	statuses := []*models.ConnectivityStatus{
		cp.Icmp,
		cp.HTTP,
	}
	for _, status := range statuses {
		if !connectivityStatusHealthy(status) {
			return false
		}
	}
	return true
}

func nodeIsHealthy(node *models.NodeStatus) bool {
	return pathIsHealthy(node.Host.PrimaryAddress) &&
		(node.Endpoint == nil || pathIsHealthy(node.Endpoint))
}

// FormatHealthStatusResponse writes a HealthStatusResponse as a string to the
// writer.
//
// 'printAll', if true, causes all nodes to be printed regardless of status
// 'succinct', if true, causes node health to be output as one line per node
// 'verbose', if true, overrides 'succinct' and prints all information
// 'maxLines', if nonzero, determines the maximum number of lines to print
func FormatHealthStatusResponse(w io.Writer, sr *models.HealthStatusResponse, printAll, succinct, verbose bool, maxLines int) {
	var healthy int
	for _, node := range sr.Nodes {
		if nodeIsHealthy(node) {
			healthy++
		}
	}
	if succinct {
		fmt.Fprintf(w, "Cluster health:\t%d/%d reachable\t(%s)\n",
			healthy, len(sr.Nodes), sr.Timestamp)
	} else {
		fmt.Fprintf(w, "Probe time:\t%s\n", sr.Timestamp)
		fmt.Fprintf(w, "Nodes:\n")
	}
	for n, node := range sr.Nodes {
		if maxLines > 0 && n > maxLines {
			break
		}
		localStr := ""
		if sr.Local != nil && node.Name == sr.Local.Name {
			localStr = " (localhost)"
		}
		if succinct {
			if printAll || healthy < len(sr.Nodes) {
				fmt.Fprintf(w, "  Name\tIP\tReachable\tEndpoints reachable\n")
			}
			if printAll || !nodeIsHealthy(node) {
				fmt.Fprintf(w, "  %s\t%s\t%t\t%t\n", node.Name,
					node.Host.PrimaryAddress.IP,
					pathIsHealthy(node.Host.PrimaryAddress),
					pathIsHealthy(node.Endpoint))
			}
		} else {
			fmt.Fprintf(w, "  %s%s:\n", node.Name, localStr)
			formatPathStatus(w, "Host", node.Host.PrimaryAddress, "    ", verbose)
			if verbose && len(node.Host.SecondaryAddresses) > 0 {
				for _, addr := range node.Host.SecondaryAddresses {
					formatPathStatus(w, "Secondary", addr, "      ", verbose)
				}
			}
			formatPathStatus(w, "Endpoint", node.Endpoint, "    ", verbose)
		}
	}
	if maxLines > 0 && len(sr.Nodes)-healthy > maxLines {
		fmt.Fprintf(w, "  ...")
	}
}
