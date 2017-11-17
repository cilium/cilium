// Copyright 2016-2017 Authors of Cilium
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
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	clientapi "github.com/cilium/cilium/api/v1/client"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/daemon/defaults"

	runtime_client "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

type Client struct {
	clientapi.Cilium
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

func formatNodeAddress(w io.Writer, elem *models.NodeAddressingElement, primary bool, prefix string) bool {
	if elem.Enabled || !primary {
		if primary {
			fmt.Fprintf(w, "%sPrimary Address:\t%s\n", prefix, elem.IP)
		} else {
			fmt.Fprintf(w, "%s%s:\n", prefix, elem.IP)
		}
		fmt.Fprintf(w, "%s Type:\t%s\n", prefix, elem.AddressType)
		if elem.AllocRange != "" {
			fmt.Fprintf(w, "%sAllocRange:\t%s\n", prefix, elem.AllocRange)
		}

		return true
	}

	return false
}

// FormatStatusResponse writes a StatusResponse as a string to the writer
func FormatStatusResponse(w io.Writer, sr *models.StatusResponse) {
	if sr.Kvstore != nil {
		fmt.Fprintf(w, "KVStore:\t%s\t%s\n", sr.Kvstore.State, sr.Kvstore.Msg)
	}
	if sr.ContainerRuntime != nil {
		fmt.Fprintf(w, "ContainerRuntime:\t%s\t%s\n",
			sr.ContainerRuntime.State, sr.ContainerRuntime.Msg)
	}
	if sr.Kubernetes != nil {
		fmt.Fprintf(w, "Kubernetes:\t%s\t%s\n", sr.Kubernetes.State, sr.Kubernetes.Msg)
		fmt.Fprintf(w, "Kubernetes APIs:\t[\"%s\"]\n", strings.Join(sr.Kubernetes.K8sAPIVersions, "\", \""))
	}
	if sr.Cilium != nil {
		fmt.Fprintf(w, "Cilium:\t%s\t%s\n", sr.Cilium.State, sr.Cilium.Msg)
	}

	if nm := sr.NodeMonitor; nm != nil {
		fmt.Fprintf(w, "NodeMonitor:\tListening for events on %d CPUs with %dx%d of shared memory\n",
			nm.Cpus, nm.Npages, nm.Pagesize)
		if nm.Lost != 0 || nm.Unknown != 0 {
			fmt.Fprintf(w, "\t%d events lost, %d unknown notifications\n", nm.Lost, nm.Unknown)
		}
	} else {
		fmt.Fprintf(w, "NodeMonitor:\tDisabled\n")
	}

	if sr.IPAM != nil {
		fmt.Fprintf(w, "Allocated IPv4 addresses:\n")
		for _, ipv4 := range sr.IPAM.IPV4 {
			fmt.Fprintf(w, " %s\n", ipv4)

		}
		fmt.Fprintf(w, "Allocated IPv6 addresses:\n")
		for _, ipv6 := range sr.IPAM.IPV6 {
			fmt.Fprintf(w, " %s\n", ipv6)
		}
	}

	if sr.Cluster != nil {
		fmt.Fprintf(w, "Known cluster nodes:\n")
		for _, node := range sr.Cluster.Nodes {
			localStr := ""
			if node.Name == sr.Cluster.Self {
				localStr = " (localhost)"
			}
			fmt.Fprintf(w, " %s%s:\n", node.Name, localStr)
			formatNodeAddress(w, node.PrimaryAddress.IPV4, true, "  ")
			formatNodeAddress(w, node.PrimaryAddress.IPV6, true, "  ")

			buf := new(bytes.Buffer)
			secondary := false
			fmt.Fprintf(buf, "  Secondary Addresses:\n")
			for _, elem := range node.SecondaryAddresses {
				if formatNodeAddress(buf, elem, false, "   ") {
					secondary = true
				}
			}
			if secondary {
				fmt.Fprintf(w, "%s", buf.String())
			}
		}
	}
}
