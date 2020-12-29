// Copyright 2016-2020 Authors of Cilium
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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	clientapi "github.com/cilium/cilium/api/v1/client"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"

	runtime_client "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

type Client struct {
	clientapi.Cilium
}

// DefaultSockPath returns default UNIX domain socket path or
// path set using CILIUM_SOCK env variable
func DefaultSockPath() string {
	// Check if environment variable points to socket
	e := os.Getenv(defaults.SockPathEnv)
	if e == "" {
		// If unset, fall back to default value
		e = defaults.SockPath
	}
	return "unix://" + e

}

func configureTransport(tr *http.Transport, proto, addr string) *http.Transport {
	if tr == nil {
		tr = &http.Transport{}
	}

	if proto == "unix" {
		// No need for compression in local communications.
		tr.DisableCompression = true
		tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial(proto, addr)
		}
	} else {
		tr.Proxy = http.ProxyFromEnvironment
		tr.DialContext = (&net.Dialer{}).DialContext
	}

	return tr
}

// NewDefaultClient creates a client with default parameters connecting to UNIX domain socket.
func NewDefaultClient() (*Client, error) {
	return NewClient("")
}

// NewDefaultClientWithTimeout creates a client with default parameters connecting to UNIX
// domain socket and waits for cilium-agent availability.
func NewDefaultClientWithTimeout(timeout time.Duration) (*Client, error) {
	timeoutAfter := time.After(timeout)
	var c *Client
	var err error
	for {
		select {
		case <-timeoutAfter:
			return nil, fmt.Errorf("failed to create cilium agent client after %f seconds timeout: %s", timeout.Seconds(), err)
		default:
		}

		c, err = NewDefaultClient()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		for {
			select {
			case <-timeoutAfter:
				return nil, fmt.Errorf("failed to create cilium agent client after %f seconds timeout: %s", timeout.Seconds(), err)
			default:
			}
			// This is an API call that we do to the cilium-agent to check
			// if it is up and running.
			_, err = c.Daemon.GetConfig(nil)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return c, nil
		}
	}
}

// NewClient creates a client for the given `host`.
// If host is nil then use SockPath provided by CILIUM_SOCK
// or the cilium default SockPath
func NewClient(host string) (*Client, error) {
	if host == "" {
		host = DefaultSockPath()
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

	if err == context.DeadlineExceeded {
		return fmt.Errorf("Cilium API client timeout exceeded")
	}

	e, _ := url.PathUnescape(err.Error())
	if strings.Contains(err.Error(), defaults.SockPath) {
		return fmt.Errorf("%s\nIs the agent running?", e)
	}
	return fmt.Errorf("%s", e)
}

func timeSince(since time.Time) string {
	out := "never"
	if !since.IsZero() {
		// Poor man's implementtion of time.Truncate(). Can be refined
		// when we rebase to go 1.9
		t := time.Since(since)
		t -= t % time.Second
		out = t.String() + " ago"
	}

	return out
}

func stateUnhealthy(state string) bool {
	return state == models.StatusStateWarning ||
		state == models.StatusStateFailure
}

func statusUnhealthy(s *models.Status) bool {
	if s != nil {
		return stateUnhealthy(s.State)
	}
	return false
}

// FormatStatusResponseBrief writes a one-line status to the writer. If
// everything ok, this is "ok", otherwise a message of the form "error in ..."
func FormatStatusResponseBrief(w io.Writer, sr *models.StatusResponse) {
	msg := ""

	switch {
	case statusUnhealthy(sr.Kvstore):
		msg = fmt.Sprintf("kvstore: %s", sr.Kvstore.Msg)
	case statusUnhealthy(sr.ContainerRuntime):
		msg = fmt.Sprintf("container runtime: %s", sr.ContainerRuntime.Msg)
	case sr.Kubernetes != nil && stateUnhealthy(sr.Kubernetes.State):
		msg = fmt.Sprintf("kubernetes: %s", sr.Kubernetes.Msg)
	case statusUnhealthy(sr.Cilium):
		msg = fmt.Sprintf("cilium: %s", sr.Cilium.Msg)
	case sr.Cluster != nil && statusUnhealthy(sr.Cluster.CiliumHealth):
		msg = fmt.Sprintf("cilium-health: %s", sr.Cluster.CiliumHealth.Msg)
	}

	// Only bother looking at controller failures if everything else is ok
	if msg == "" {
		for _, ctrl := range sr.Controllers {
			if ctrl.Status == nil {
				continue
			}
			if ctrl.Status.LastFailureMsg != "" {
				msg = fmt.Sprintf("controller %s: %s",
					ctrl.Name, ctrl.Status.LastFailureMsg)
				break
			}
		}
	}

	if msg == "" {
		fmt.Fprintf(w, "OK\n")
	} else {
		fmt.Fprintf(w, "error in %s\n", msg)
	}
}

func clusterReadiness(cluster *models.RemoteCluster) string {
	if !cluster.Ready {
		return "not-ready"
	}
	return "ready"
}

func numReadyClusters(clustermesh *models.ClusterMeshStatus) int {
	numReady := 0
	for _, cluster := range clustermesh.Clusters {
		if cluster.Ready {
			numReady++
		}
	}
	return numReady
}

// FormatStatusResponse writes a StatusResponse as a string to the writer.
//
// The parameters 'allAddresses', 'allControllers', 'allNodes', respectively,
// cause all details about that aspect of the status to be printed to the
// terminal. For each of these, if they are false then only a summary will be
// printed, with perhaps some detail if there are errors.
func FormatStatusResponse(w io.Writer, sr *models.StatusResponse, allAddresses, allControllers, allNodes, allRedirects, allClusters bool) {
	if sr.Kvstore != nil {
		fmt.Fprintf(w, "KVStore:\t%s\t%s\n", sr.Kvstore.State, sr.Kvstore.Msg)
	}
	if sr.ContainerRuntime != nil {
		fmt.Fprintf(w, "ContainerRuntime:\t%s\t%s\n",
			sr.ContainerRuntime.State, sr.ContainerRuntime.Msg)
	}
	if sr.Kubernetes != nil {
		fmt.Fprintf(w, "Kubernetes:\t%s\t%s\n", sr.Kubernetes.State, sr.Kubernetes.Msg)
		if sr.Kubernetes.State != models.K8sStatusStateDisabled {
			sort.Strings(sr.Kubernetes.K8sAPIVersions)
			fmt.Fprintf(w, "Kubernetes APIs:\t[\"%s\"]\n", strings.Join(sr.Kubernetes.K8sAPIVersions, "\", \""))
		}
		if sr.KubeProxyReplacement != nil {
			features := []string{}

			if np := sr.KubeProxyReplacement.Features.NodePort; np.Enabled {
				mode := np.Mode
				if mode == models.KubeProxyReplacementFeaturesNodePortModeHYBRID {
					mode = strings.Title(mode)
				}
				features = append(features,
					fmt.Sprintf("NodePort (%s, %d-%d, XDP: %s)",
						mode, np.PortMin, np.PortMax, np.Acceleration))
			}

			if sr.KubeProxyReplacement.Features.HostPort.Enabled {
				features = append(features, "HostPort")
			}

			if sr.KubeProxyReplacement.Features.ExternalIPs.Enabled {
				features = append(features, "ExternalIPs")
			}

			if hs := sr.KubeProxyReplacement.Features.HostReachableServices; hs.Enabled {
				features = append(features, fmt.Sprintf("HostReachableServices (%s)",
					strings.Join(hs.Protocols, ", ")))
			}

			if sr.KubeProxyReplacement.Features.SessionAffinity.Enabled {
				features = append(features, "SessionAffinity")
			}

			devices := ""
			for i, dev := range sr.KubeProxyReplacement.Devices {
				devices += dev
				if dev == sr.KubeProxyReplacement.DirectRoutingDevice {
					devices += " (DR)"
				}
				if i+1 != len(sr.KubeProxyReplacement.Devices) {
					devices += ", "
				}

			}

			fmt.Fprintf(w, "KubeProxyReplacement:\t%s\t[%s]\t[%s]\n",
				sr.KubeProxyReplacement.Mode, devices, strings.Join(features, ", "))
		}
	}
	if sr.Cilium != nil {
		fmt.Fprintf(w, "Cilium:\t%s   %s\n", sr.Cilium.State, sr.Cilium.Msg)
	}

	if sr.Stale != nil {
		sortedProbes := make([]string, 0, len(sr.Stale))
		for probe := range sr.Stale {
			sortedProbes = append(sortedProbes, probe)
		}
		sort.Strings(sortedProbes)

		stalesStr := make([]string, 0, len(sr.Stale))
		for _, probe := range sortedProbes {
			stalesStr = append(stalesStr, fmt.Sprintf("%q since %s", probe, sr.Stale[probe]))
		}

		fmt.Fprintf(w, "Stale status:\t%s\n", strings.Join(stalesStr, ", "))
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

	if sr.Cluster != nil {
		if sr.Cluster.CiliumHealth != nil {
			ch := sr.Cluster.CiliumHealth
			fmt.Fprintf(w, "Cilium health daemon:\t%s\t%s\n", ch.State, ch.Msg)
		}
	}

	if sr.Ipam != nil {
		fmt.Fprintf(w, "IPAM:\t%s\n", sr.Ipam.Status)
		if allAddresses {
			fmt.Fprintf(w, "Allocated addresses:\n")
			out := []string{}
			for ip, owner := range sr.Ipam.Allocations {
				out = append(out, fmt.Sprintf("  %s (%s)", ip, owner))
			}
			sort.Strings(out)
			for _, line := range out {
				fmt.Fprintln(w, line)
			}
		}
	}

	if sr.ClusterMesh != nil {
		fmt.Fprintf(w, "ClusterMesh:\t%d/%d clusters ready, %d global-services\n",
			numReadyClusters(sr.ClusterMesh), len(sr.ClusterMesh.Clusters), sr.ClusterMesh.NumGlobalServices)

		for _, cluster := range sr.ClusterMesh.Clusters {
			if allClusters || !cluster.Ready {
				fmt.Fprintf(w, "   %s: %s, %d nodes, %d identities, %d services, %d failures (last: %s)\n",
					cluster.Name, clusterReadiness(cluster), cluster.NumNodes,
					cluster.NumIdentities, cluster.NumSharedServices,
					cluster.NumFailures, timeSince(time.Time(cluster.LastFailure)))
				fmt.Fprintf(w, "   └  %s\n", cluster.Status)
			}
		}
	}

	if sr.Masquerading != nil {
		var status string
		if !sr.Masquerading.Enabled {
			status = "Disabled"
		} else if sr.Masquerading.Mode == models.MasqueradingModeBPF {
			if sr.Masquerading.IPMasqAgent {
				status = "BPF (ip-masq-agent)"
			} else {
				status = "BPF"
			}
			if sr.KubeProxyReplacement != nil {
				status += fmt.Sprintf("\t[%s]\t%s",
					strings.Join(sr.KubeProxyReplacement.Devices, ", "),
					sr.Masquerading.SnatExclusionCidr)
			}

		} else if sr.Masquerading.Mode == models.MasqueradingModeIptables {
			status = "IPTables"
		}
		fmt.Fprintf(w, "Masquerading:\t%s\n", status)
	}

	if sr.Controllers != nil {
		nFailing, out := 0, []string{"  Name\tLast success\tLast error\tCount\tMessage\n"}
		for _, ctrl := range sr.Controllers {
			status := ctrl.Status
			if status == nil {
				continue
			}

			if status.ConsecutiveFailureCount > 0 {
				nFailing++
			} else if !allControllers {
				continue
			}

			failSince := timeSince(time.Time(status.LastFailureTimestamp))
			successSince := timeSince(time.Time(status.LastSuccessTimestamp))

			err := "no error"
			if status.LastFailureMsg != "" {
				err = status.LastFailureMsg
			}

			out = append(out, fmt.Sprintf("  %s\t%s\t%s\t%d\t%s\t\n",
				ctrl.Name, successSince, failSince, status.ConsecutiveFailureCount, err))
		}

		nOK := len(sr.Controllers) - nFailing
		fmt.Fprintf(w, "Controller Status:\t%d/%d healthy\n", nOK, len(sr.Controllers))
		if len(out) > 1 {
			tab := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
			sort.Strings(out)
			for _, s := range out {
				fmt.Fprint(tab, s)
			}
			tab.Flush()
		}

	}

	if sr.Proxy != nil {
		fmt.Fprintf(w, "Proxy Status:\tOK, ip %s, %d redirects active on ports %s\n",
			sr.Proxy.IP, sr.Proxy.TotalRedirects, sr.Proxy.PortRange)
		if allRedirects && sr.Proxy.TotalRedirects > 0 {
			out := make([]string, 0, len(sr.Proxy.Redirects)+1)
			for _, r := range sr.Proxy.Redirects {
				out = append(out, fmt.Sprintf("  %s\t%s\t%d\n", r.Proxy, r.Name, r.ProxyPort))
			}
			tab := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
			fmt.Fprint(tab, "  Protocol\tRedirect\tProxy Port\n")
			sort.Strings(out)
			for _, s := range out {
				fmt.Fprint(tab, s)
			}
			tab.Flush()
		}
	} else {
		fmt.Fprintf(w, "Proxy Status:\tNo managed proxy redirect\n")
	}

	if sr.Hubble != nil {
		var fields []string

		state := sr.Hubble.State
		if sr.Hubble.Msg != "" {
			state = fmt.Sprintf("%s %s", state, sr.Hubble.Msg)
		}
		fields = append(fields, state)

		if o := sr.Hubble.Observer; o != nil {
			var observer []string

			if o.MaxFlows > 0 {
				observer = append(observer, fmt.Sprintf("Current/Max Flows: %d/%d (%.2f%%)",
					o.CurrentFlows, o.MaxFlows, (float64(o.CurrentFlows)/float64(o.MaxFlows))*100))
			}
			if o.Uptime > 0 {
				observer = append(observer, fmt.Sprintf("Flows/s: %.2f",
					float64(o.SeenFlows)/time.Duration(o.Uptime).Seconds()))
			}

			fields = append(fields, strings.Join(observer, ", "))
		}

		if sr.Hubble.Metrics != nil {
			fields = append(fields, fmt.Sprintf("Metrics: %s", sr.Hubble.Metrics.State))
		}

		fmt.Fprintf(w, "Hubble:\t%s\n", strings.Join(fields, "\t"))
	}
}
