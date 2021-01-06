// Copyright 2018 Authors of Cilium
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
	"sort"
	"strings"
	"time"

	clientapi "github.com/cilium/cilium/api/v1/health/client"
	"github.com/cilium/cilium/api/v1/health/models"
	"github.com/cilium/cilium/pkg/health/defaults"

	runtime_client "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

type ConnectivityStatusType int

const (
	ipUnavailable = "Unavailable"

	ConnStatusReachable   ConnectivityStatusType = 0
	ConnStatusUnreachable ConnectivityStatusType = 1
	ConnStatusUnknown     ConnectivityStatusType = 2
)

func (c ConnectivityStatusType) String() string {
	switch c {
	case ConnStatusReachable:
		return "reachable"
	case ConnStatusUnreachable:
		return "unreachable"
	default:
		return "unknown"
	}
}

// Client is a client for cilium health
type Client struct {
	clientapi.CiliumHealthAPI
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

func GetConnectivityStatusType(cs *models.ConnectivityStatus) ConnectivityStatusType {
	// If the connecticity status is nil, it means that there was no
	// successful probe, but also no failed probe with a concrete reason. In
	// that case, the status is unknown and it usually means that the new
	// is still in the beginning of the bootstraping process.
	if cs == nil {
		return ConnStatusUnknown
	}
	// Empty status means successful probe.
	if cs.Status == "" {
		return ConnStatusReachable
	}
	// Non-empty status means that there was an explicit reason of failure.
	return ConnStatusUnreachable
}

func GetPathConnectivityStatusType(cp *models.PathStatus) ConnectivityStatusType {
	if cp == nil {
		return ConnStatusUnreachable
	}
	statuses := []*models.ConnectivityStatus{
		cp.Icmp,
		cp.HTTP,
	}
	// Initially assume healthy status.
	status := ConnStatusReachable
	for _, cs := range statuses {
		switch GetConnectivityStatusType(cs) {
		case ConnStatusUnreachable:
			// If any status is unreachable, return it immediately.
			return ConnStatusUnreachable
		case ConnStatusUnknown:
			// If the status is unknown, prepare to return it. It's
			// going to be returned if there is no unreachable
			// status in next iterations.
			status = ConnStatusUnknown
		}
	}
	return status
}

func formatConnectivityStatus(w io.Writer, cs *models.ConnectivityStatus, path, indent string) {
	status := cs.Status
	switch GetConnectivityStatusType(cs) {
	case ConnStatusReachable:
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

	if cp.Icmp != nil {
		formatConnectivityStatus(w, cp.Icmp, "ICMP to stack", indent)
	}
	if cp.HTTP != nil {
		formatConnectivityStatus(w, cp.HTTP, "HTTP to agent", indent)
	}
}

// pathIsHealthyOrUnknown checks whether ICMP and TCP(HTTP) connectivity to the
// given path is available or had no explicit error status (which usually is the
// case when the new node is provisioned).
func pathIsHealthyOrUnknown(cp *models.PathStatus) bool {
	if cp == nil {
		return false
	}

	statuses := []*models.ConnectivityStatus{
		cp.Icmp,
		cp.HTTP,
	}
	for _, status := range statuses {
		switch GetConnectivityStatusType(status) {
		case ConnStatusUnreachable:
			return false
		}
	}
	return true
}

func nodeIsHealthy(node *models.NodeStatus) bool {
	return pathIsHealthyOrUnknown(GetHostPrimaryAddress(node)) &&
		(node.Endpoint == nil || pathIsHealthyOrUnknown(node.Endpoint))
}

func nodeIsLocalhost(node *models.NodeStatus, self *models.SelfStatus) bool {
	return self != nil && node.Name == self.Name
}

func getPrimaryAddressIP(node *models.NodeStatus) string {
	if node.Host == nil || node.Host.PrimaryAddress == nil {
		return ipUnavailable
	}

	return node.Host.PrimaryAddress.IP
}

// GetHostPrimaryAddress returns the PrimaryAddress for the Host within node.
// If node.Host is nil, returns nil.
func GetHostPrimaryAddress(node *models.NodeStatus) *models.PathStatus {
	if node.Host == nil {
		return nil
	}

	return node.Host.PrimaryAddress
}

func formatNodeStatus(w io.Writer, node *models.NodeStatus, printAll, succinct, verbose, localhost bool) {
	localStr := ""
	if localhost {
		localStr = " (localhost)"
	}
	if succinct {
		if printAll || !nodeIsHealthy(node) {

			fmt.Fprintf(w, "  %s%s\t%s\t%s\t%s\n", node.Name,
				localStr, getPrimaryAddressIP(node),
				GetPathConnectivityStatusType(GetHostPrimaryAddress(node)).String(),
				GetPathConnectivityStatusType(node.Endpoint).String())
		}
	} else {
		fmt.Fprintf(w, "  %s%s:\n", node.Name, localStr)
		formatPathStatus(w, "Host", GetHostPrimaryAddress(node), "    ", verbose)
		if verbose && node.Host != nil {
			for _, addr := range node.Host.SecondaryAddresses {
				formatPathStatus(w, "Secondary", addr, "      ", verbose)
			}
		}
		formatPathStatus(w, "Endpoint", node.Endpoint, "    ", verbose)
	}
}

// FormatHealthStatusResponse writes a HealthStatusResponse as a string to the
// writer.
//
// 'printAll', if true, causes all nodes to be printed regardless of status
// 'succinct', if true, causes node health to be output as one line per node
// 'verbose', if true, overrides 'succinct' and prints all information
// 'maxLines', if nonzero, determines the maximum number of lines to print
func FormatHealthStatusResponse(w io.Writer, sr *models.HealthStatusResponse, printAll, succinct, verbose bool, maxLines int) {
	var (
		healthy   int
		localhost *models.NodeStatus
	)
	for _, node := range sr.Nodes {
		if nodeIsHealthy(node) {
			healthy++
		}
		if nodeIsLocalhost(node, sr.Local) {
			localhost = node
		}
	}
	if succinct {
		fmt.Fprintf(w, "Cluster health:\t%d/%d reachable\t(%s)\n",
			healthy, len(sr.Nodes), sr.Timestamp)
		if printAll || healthy < len(sr.Nodes) {
			fmt.Fprintf(w, "  Name\tIP\tNode\tEndpoints\n")
		}
	} else {
		fmt.Fprintf(w, "Probe time:\t%s\n", sr.Timestamp)
		fmt.Fprintf(w, "Nodes:\n")
	}

	if localhost != nil {
		formatNodeStatus(w, localhost, printAll, succinct, verbose, true)
		maxLines--
	}

	nodes := sr.Nodes
	sort.Slice(nodes, func(i, j int) bool {
		return strings.Compare(nodes[i].Name, nodes[j].Name) < 0
	})
	for n, node := range nodes {
		if maxLines > 0 && n > maxLines {
			break
		}
		if node == localhost {
			continue
		}
		formatNodeStatus(w, node, printAll, succinct, verbose, false)
	}
	if maxLines > 0 && len(sr.Nodes)-healthy > maxLines {
		fmt.Fprintf(w, "  ...")
	}
}

// GetAndFormatHealthStatus fetches the health status from the cilium-health
// daemon via the default channel and formats its output as a string to the
// writer.
//
// 'succinct', 'verbose' and 'maxLines' are handled the same as in
// FormatHealthStatusResponse().
func GetAndFormatHealthStatus(w io.Writer, succinct, verbose bool, maxLines int) {
	client, err := NewClient("")
	if err != nil {
		fmt.Fprintf(w, "Cluster health:\t\t\tClient error: %s\n", err)
		return
	}
	hr, err := client.Connectivity.GetStatus(nil)
	if err != nil {
		// The regular `cilium status` output will print the reason why.
		fmt.Fprintf(w, "Cluster health:\t\t\tWarning\tcilium-health daemon unreachable\n")
		return
	}
	FormatHealthStatusResponse(w, hr.Payload, verbose, succinct, verbose, maxLines)
}
