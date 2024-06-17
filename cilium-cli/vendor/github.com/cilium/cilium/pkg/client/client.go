// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
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

	runtime_client "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	clientapi "github.com/cilium/cilium/api/v1/client"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
)

type Client struct {
	clientapi.CiliumAPI
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
			return nil, fmt.Errorf("failed to create cilium agent client after %f seconds timeout: %w", timeout.Seconds(), err)
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
				return nil, fmt.Errorf("failed to create cilium agent client after %f seconds timeout: %w", timeout.Seconds(), err)
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
	clientTrans, err := NewRuntime(WithHost(host))
	return &Client{*clientapi.New(clientTrans, strfmt.Default)}, err
}

type runtimeOptions struct {
	host     string
	basePath string
}

func WithHost(host string) func(options *runtimeOptions) {
	return func(options *runtimeOptions) {
		options.host = host
	}
}

func WithBasePath(basePath string) func(options *runtimeOptions) {
	return func(options *runtimeOptions) {
		options.basePath = basePath
	}
}

func NewTransport(host string) (*http.Transport, error) {
	if host == "" {
		host = DefaultSockPath()
	}
	schema, host, found := strings.Cut(host, "://")
	if !found {
		return nil, fmt.Errorf("invalid host format '%s'", host)
	}
	switch schema {
	case "tcp":
		if _, err := url.Parse("tcp://" + host); err != nil {
			return nil, err
		}
		host = "http://" + host
	case "unix":
	}
	return configureTransport(nil, schema, host), nil
}

func NewRuntime(opts ...func(options *runtimeOptions)) (*runtime_client.Runtime, error) {
	r := runtimeOptions{}
	for _, opt := range opts {
		opt(&r)
	}

	basePath := r.basePath
	if basePath == "" {
		basePath = clientapi.DefaultBasePath
	}

	host := r.host
	if host == "" {
		host = DefaultSockPath()
	}

	_, hostHeader, found := strings.Cut(host, "://")
	if !found {
		return nil, fmt.Errorf("invalid host format '%s'", host)
	}
	if strings.HasPrefix(host, "unix") {
		// For local communication (unix domain sockets), the hostname is not used. Leave
		// Host header empty because otherwise it would be rejected by net/http client-side
		// sanitization, see https://go.dev/issue/60374.
		hostHeader = "localhost"
	}

	transport, err := NewTransport(host)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Transport: transport}
	clientTrans := runtime_client.NewWithClient(hostHeader, basePath,
		clientapi.DefaultSchemes, httpClient)
	return clientTrans, nil
}

// Hint tries to improve the error message displayed to the user.
func Hint(err error) error {
	if err == nil {
		return err
	}

	if errors.Is(err, context.DeadlineExceeded) {
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
		t := time.Since(since)
		out = t.Truncate(time.Second).String() + " ago"
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

func NumReadyClusters(clusters []*models.RemoteCluster) int {
	numReady := 0
	for _, cluster := range clusters {
		if cluster.Ready {
			numReady++
		}
	}
	return numReady
}

type StatusDetails struct {
	// AllAddress causes all addresses to be printed by FormatStatusResponse.
	AllAddresses bool
	// AllControllers causes all controllers to be printed by FormatStatusResponse.
	AllControllers bool
	// AllNodes causes all nodes to be printed by FormatStatusResponse.
	AllNodes bool
	// AllRedirects causes all redirects to be printed by FormatStatusResponse.
	AllRedirects bool
	// AllClusters causes all clusters to be printed by FormatStatusResponse.
	AllClusters bool
	// BPFMapDetails causes BPF map details to be printed by FormatStatusResponse.
	BPFMapDetails bool
	// KubeProxyReplacementDetails causes BPF kube-proxy details to be printed by FormatStatusResponse.
	KubeProxyReplacementDetails bool
	// ClockSourceDetails causes BPF time-keeping internals to be printed by FormatStatusResponse.
	ClockSourceDetails bool
}

var (
	// StatusAllDetails causes no additional status details to be printed by
	// FormatStatusResponse.
	StatusNoDetails = StatusDetails{}
	// StatusAllDetails causes all status details to be printed by FormatStatusResponse.
	StatusAllDetails = StatusDetails{
		AllAddresses:                true,
		AllControllers:              true,
		AllNodes:                    true,
		AllRedirects:                true,
		AllClusters:                 true,
		BPFMapDetails:               true,
		KubeProxyReplacementDetails: true,
		ClockSourceDetails:          true,
	}
)

// FormatStatusResponse writes a StatusResponse as a string to the writer. The bit mask sd controls
// whether a additional details are printed about a certain aspect of the status. In case there are
// errors, some details may be printed regardless of the value of sd.
func FormatStatusResponse(w io.Writer, sr *models.StatusResponse, sd StatusDetails) {
	if sr.Kvstore != nil {
		fmt.Fprintf(w, "KVStore:\t%s\t%s\n", sr.Kvstore.State, sr.Kvstore.Msg)
	}
	if sr.ContainerRuntime != nil {
		fmt.Fprintf(w, "ContainerRuntime:\t%s\t%s\n",
			sr.ContainerRuntime.State, sr.ContainerRuntime.Msg)
	}

	kubeProxyDevices := ""
	if sr.Kubernetes != nil {
		fmt.Fprintf(w, "Kubernetes:\t%s\t%s\n", sr.Kubernetes.State, sr.Kubernetes.Msg)
		if sr.Kubernetes.State != models.K8sStatusStateDisabled {
			sort.Strings(sr.Kubernetes.K8sAPIVersions)
			fmt.Fprintf(w, "Kubernetes APIs:\t[\"%s\"]\n", strings.Join(sr.Kubernetes.K8sAPIVersions, "\", \""))
		}

	}
	if sr.KubeProxyReplacement != nil {
		devices := ""
		if sr.KubeProxyReplacement.Mode != models.KubeProxyReplacementModeFalse {
			for i, dev := range sr.KubeProxyReplacement.DeviceList {
				kubeProxyDevices += fmt.Sprintf("%s %s", dev.Name, strings.Join(dev.IP, " "))
				if dev.Name == sr.KubeProxyReplacement.DirectRoutingDevice {
					kubeProxyDevices += " (Direct Routing)"
				}
				if i+1 != len(sr.KubeProxyReplacement.Devices) {
					kubeProxyDevices += ", "
				}
			}
			if len(sr.KubeProxyReplacement.DeviceList) > 0 {
				devices = "[" + kubeProxyDevices + "]"
			}
		}
		fmt.Fprintf(w, "KubeProxyReplacement:\t%s\t%s\n",
			sr.KubeProxyReplacement.Mode, devices)
	}
	if sr.HostFirewall != nil {
		fmt.Fprintf(w, "Host firewall:\t%s", sr.HostFirewall.Mode)
		if sr.HostFirewall.Mode != models.HostFirewallModeDisabled {
			fmt.Fprintf(w, "\t[%s]", strings.Join(sr.HostFirewall.Devices, ", "))
		}
		fmt.Fprintf(w, "\n")
	}

	if sr.Srv6 != nil {
		var fields []string

		status := "Disabled"
		fields = append(fields, status)

		if sr.Srv6.Enabled {
			fields[0] = "Enabled"
			fields = append(fields, fmt.Sprintf("[encap-mode: %s]", sr.Srv6.Srv6EncapMode))
		}

		fmt.Fprintf(w, "SRv6:\t%s\n", strings.Join(fields, "\t"))
	}

	if sr.CniChaining != nil {
		fmt.Fprintf(w, "CNI Chaining:\t%s\n", sr.CniChaining.Mode)
	}

	if sr.CniFile != nil {
		fmt.Fprintf(w, "CNI Config file:\t%s\n", sr.CniFile.Msg)
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
		if sd.AllAddresses {
			fmt.Fprintf(w, "Allocated addresses:\n")
			out := make([]string, 0, len(sr.Ipam.Allocations))
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
			NumReadyClusters(sr.ClusterMesh.Clusters), len(sr.ClusterMesh.Clusters), sr.ClusterMesh.NumGlobalServices)

		verbosity := RemoteClustersStatusNotReadyOnly
		if sd.AllClusters {
			verbosity = RemoteClustersStatusVerbose
		}

		FormatStatusResponseRemoteClusters(w, sr.ClusterMesh.Clusters, verbosity)
	}

	if sr.IPV4BigTCP != nil {
		status := "Disabled"
		if sr.IPV4BigTCP.Enabled {
			max := fmt.Sprintf("[%d]", sr.IPV4BigTCP.MaxGSO)
			if sr.IPV4BigTCP.MaxGRO != sr.IPV4BigTCP.MaxGSO {
				max = fmt.Sprintf("[%d, %d]", sr.IPV4BigTCP.MaxGRO, sr.IPV4BigTCP.MaxGSO)
			}
			status = fmt.Sprintf("Enabled\t%s", max)
		}
		fmt.Fprintf(w, "IPv4 BIG TCP:\t%s\n", status)
	}

	if sr.IPV6BigTCP != nil {
		status := "Disabled"
		if sr.IPV6BigTCP.Enabled {
			max := fmt.Sprintf("[%d]", sr.IPV6BigTCP.MaxGSO)
			if sr.IPV6BigTCP.MaxGRO != sr.IPV6BigTCP.MaxGSO {
				max = fmt.Sprintf("[%d, %d]", sr.IPV6BigTCP.MaxGRO, sr.IPV6BigTCP.MaxGSO)
			}
			status = fmt.Sprintf("Enabled\t%s", max)
		}
		fmt.Fprintf(w, "IPv6 BIG TCP:\t%s\n", status)
	}

	if sr.BandwidthManager != nil {
		var status string
		if !sr.BandwidthManager.Enabled {
			status = "Disabled"
		} else {
			status = fmt.Sprintf("EDT with BPF [%s] [%s]",
				strings.ToUpper(sr.BandwidthManager.CongestionControl),
				strings.Join(sr.BandwidthManager.Devices, ", "))
		}
		fmt.Fprintf(w, "BandwidthManager:\t%s\n", status)
	}

	if sr.Routing != nil {
		status := "Network: " + sr.Routing.InterHostRoutingMode
		if sr.Routing.InterHostRoutingMode == models.RoutingInterHostRoutingModeTunnel {
			status = status + " [" + sr.Routing.TunnelProtocol + "]"
		}
		status = status + "\tHost: " + sr.Routing.IntraHostRoutingMode

		fmt.Fprintf(w, "Routing:\t%s\n", status)
	}

	if sr.AttachMode != "" {
		status := "Legacy TC"
		if sr.AttachMode == models.AttachModeTcx {
			status = "TCX"
		}
		fmt.Fprintf(w, "Attach Mode:\t%s\n", status)
	}

	if sr.DatapathMode != "" {
		status := "?"
		if sr.DatapathMode == models.DatapathModeVeth {
			status = "veth"
		} else if sr.DatapathMode == models.DatapathModeNetkitDashL2 {
			status = "netkit-l2"
		} else if sr.DatapathMode == models.DatapathModeNetkit {
			status = "netkit"
		}
		fmt.Fprintf(w, "Device Mode:\t%s\n", status)
	}

	if sr.Masquerading != nil {
		var status string

		enabled := func(enabled bool) string {
			if enabled {
				return "Enabled"
			}
			return "Disabled"
		}

		if sr.Masquerading.EnabledProtocols == nil {
			status = enabled(sr.Masquerading.Enabled)
		} else if !sr.Masquerading.EnabledProtocols.IPV4 && !sr.Masquerading.EnabledProtocols.IPV6 {
			status = enabled(false)
		} else {
			if sr.Masquerading.Mode == models.MasqueradingModeBPF {
				if sr.Masquerading.IPMasqAgent {
					status = "BPF (ip-masq-agent)"
				} else {
					status = "BPF"
				}
				if sr.KubeProxyReplacement != nil {
					// When BPF Masquerading is enabled we don't do any masquerading for IPv6
					// traffic so no SNAT Exclusion IPv6 CIDR is listed in status output.
					devStr := ""
					for i, dev := range sr.KubeProxyReplacement.DeviceList {
						devStr += dev.Name
						if i+1 != len(sr.KubeProxyReplacement.DeviceList) {
							devStr += ", "
						}
					}
					status += fmt.Sprintf("\t[%s]\t%s",
						devStr,
						sr.Masquerading.SnatExclusionCidrV4)
				}

			} else if sr.Masquerading.Mode == models.MasqueradingModeIptables {
				status = "IPTables"
			}

			status = fmt.Sprintf("%s [IPv4: %s, IPv6: %s]", status,
				enabled(sr.Masquerading.EnabledProtocols.IPV4), enabled(sr.Masquerading.EnabledProtocols.IPV6))
		}
		fmt.Fprintf(w, "Masquerading:\t%s\n", status)
	}

	if sd.ClockSourceDetails && sr.ClockSource != nil {
		status := sr.ClockSource.Mode
		if sr.ClockSource.Mode == models.ClockSourceModeJiffies {
			status = fmt.Sprintf("%s\t[%d Hz]",
				sr.ClockSource.Mode, sr.ClockSource.Hertz)
		}
		fmt.Fprintf(w, "Clock Source for BPF:\t%s\n", status)
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
			} else if !sd.AllControllers {
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
		fmt.Fprintf(w, "Proxy Status:\tOK, ip %s, %d redirects active on ports %s, Envoy: %s\n",
			sr.Proxy.IP, sr.Proxy.TotalRedirects, sr.Proxy.PortRange, sr.Proxy.EnvoyDeploymentMode)
		if sd.AllRedirects && sr.Proxy.TotalRedirects > 0 {
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

	if sr.IdentityRange != nil {
		fmt.Fprintf(w, "Global Identity Range:\tmin %d, max %d\n",
			sr.IdentityRange.MinIdentity, sr.IdentityRange.MaxIdentity)
	} else {
		fmt.Fprintf(w, "Global Identity Range:\tUnknown\n")
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

	if sd.KubeProxyReplacementDetails && sr.Kubernetes != nil && sr.KubeProxyReplacement != nil {
		var selection, mode, dsrMode, xdp string

		lb := "Disabled"
		cIP := "Enabled"
		nPort := "Disabled"
		if np := sr.KubeProxyReplacement.Features.NodePort; np.Enabled {
			selection = np.Algorithm
			if selection == models.KubeProxyReplacementFeaturesNodePortAlgorithmMaglev {
				selection = fmt.Sprintf("%s (Table Size: %d)", np.Algorithm, np.LutSize)
			}
			xdp = np.Acceleration
			mode = np.Mode
			if mode == models.KubeProxyReplacementFeaturesNodePortModeDSR ||
				mode == models.KubeProxyReplacementFeaturesNodePortModeHybrid {
				dsrMode = np.DsrMode
			}
			nPort = fmt.Sprintf("Enabled (Range: %d-%d)", np.PortMin, np.PortMax)
			lb = "Enabled"
		}

		affinity := "Disabled"
		if sr.KubeProxyReplacement.Features.SessionAffinity.Enabled {
			affinity = "Enabled"
		}

		hPort := "Disabled"
		if sr.KubeProxyReplacement.Features.HostPort.Enabled {
			hPort = "Enabled"
		}

		eIP := "Disabled"
		if sr.KubeProxyReplacement.Features.ExternalIPs.Enabled {
			eIP = "Enabled"
		}

		socketLB := "Disabled"
		if slb := sr.KubeProxyReplacement.Features.SocketLB; slb.Enabled {
			socketLB = "Enabled"
		}

		socketLBTracing := "Disabled"
		if st := sr.KubeProxyReplacement.Features.SocketLBTracing; st.Enabled {
			socketLBTracing = "Enabled"
		}

		socketLBCoverage := "Full"
		if sr.KubeProxyReplacement.Features.BpfSocketLBHostnsOnly {
			socketLBCoverage = "Hostns-only"
		}

		gracefulTerm := "Disabled"
		if sr.KubeProxyReplacement.Features.GracefulTermination.Enabled {
			gracefulTerm = "Enabled"
		}

		nat46X64 := "Disabled"
		nat46X64GW := "Disabled"
		nat46X64SVC := "Disabled"
		prefixes := ""
		if sr.KubeProxyReplacement.Features.Nat46X64.Enabled {
			nat46X64 = "Enabled"
			if svc := sr.KubeProxyReplacement.Features.Nat46X64.Service; svc.Enabled {
				nat46X64SVC = "Enabled"
			}
			if gw := sr.KubeProxyReplacement.Features.Nat46X64.Gateway; gw.Enabled {
				nat46X64GW = "Enabled"
				prefixes = strings.Join(gw.Prefixes, ", ")
			}
		}

		fmt.Fprintf(w, "KubeProxyReplacement Details:\n")
		tab := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		fmt.Fprintf(tab, "  Status:\t%s\n", sr.KubeProxyReplacement.Mode)
		fmt.Fprintf(tab, "  Socket LB:\t%s\n", socketLB)
		fmt.Fprintf(tab, "  Socket LB Tracing:\t%s\n", socketLBTracing)
		fmt.Fprintf(tab, "  Socket LB Coverage:\t%s\n", socketLBCoverage)
		if kubeProxyDevices != "" {
			fmt.Fprintf(tab, "  Devices:\t%s\n", kubeProxyDevices)
		}
		if mode != "" {
			fmt.Fprintf(tab, "  Mode:\t%s\n", mode)
		}
		if dsrMode != "" {
			fmt.Fprintf(tab, "    DSR Dispatch Mode:\t%s\n", dsrMode)
		}
		if selection != "" {
			fmt.Fprintf(tab, "  Backend Selection:\t%s\n", selection)
		}
		fmt.Fprintf(tab, "  Session Affinity:\t%s\n", affinity)
		fmt.Fprintf(tab, "  Graceful Termination:\t%s\n", gracefulTerm)
		if nat46X64 == "Disabled" {
			fmt.Fprintf(tab, "  NAT46/64 Support:\t%s\n", nat46X64)
		} else {
			fmt.Fprintf(tab, "  NAT46/64 Support:\n")
			fmt.Fprintf(tab, "  - Services:\t%s\n", nat46X64SVC)
			fmt.Fprintf(tab, "  - Gateway:\t%s\n", nat46X64GW)
			if nat46X64GW == "Enabled" && prefixes != "" {
				fmt.Fprintf(tab, "    Prefixes:\t%s\n", prefixes)
			}
		}
		if xdp != "" {
			fmt.Fprintf(tab, "  XDP Acceleration:\t%s\n", xdp)
		}
		fmt.Fprintf(tab, "  Services:\n")
		fmt.Fprintf(tab, "  - ClusterIP:\t%s\n", cIP)
		fmt.Fprintf(tab, "  - NodePort:\t%s \n", nPort)
		fmt.Fprintf(tab, "  - LoadBalancer:\t%s \n", lb)
		fmt.Fprintf(tab, "  - externalIPs:\t%s \n", eIP)
		fmt.Fprintf(tab, "  - HostPort:\t%s\n", hPort)
		tab.Flush()
	}

	if sd.BPFMapDetails && sr.BpfMaps != nil {
		dynamicSizingStatus := "off"
		ratio := sr.BpfMaps.DynamicSizeRatio
		if 0.0 < ratio && ratio <= 1.0 {
			dynamicSizingStatus = fmt.Sprintf("on (ratio: %f)", ratio)
		}
		fmt.Fprintf(w, "BPF Maps:\tdynamic sizing: %s\n", dynamicSizingStatus)
		tab := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		fmt.Fprintf(tab, "  Name\tSize\n")
		for _, m := range sr.BpfMaps.Maps {
			fmt.Fprintf(tab, "  %s\t%d\n", m.Name, m.Size)
		}
		tab.Flush()
	}

	if sr.Encryption != nil {
		var fields []string

		if sr.Encryption.Msg != "" {
			fields = append(fields, sr.Encryption.Msg)
		} else if wg := sr.Encryption.Wireguard; wg != nil {
			fields = append(fields, fmt.Sprintf("[NodeEncryption: %s", wg.NodeEncryption))
			ifaces := make([]string, 0, len(wg.Interfaces))
			for _, i := range wg.Interfaces {
				iface := fmt.Sprintf("%s (Pubkey: %s, Port: %d, Peers: %d)",
					i.Name, i.PublicKey, i.ListenPort, i.PeerCount)
				ifaces = append(ifaces, iface)
			}
			fields = append(fields, fmt.Sprintf("%s]", strings.Join(ifaces, ", ")))
		}

		fmt.Fprintf(w, "Encryption:\t%s\t%s\n", sr.Encryption.Mode, strings.Join(fields, ", "))
	}
}

// RemoteClustersStatusVerbosity specifies the verbosity when formatting the remote clusters status information.
type RemoteClustersStatusVerbosity uint

const (
	// RemoteClustersStatusVerbose outputs all remote clusters information.
	RemoteClustersStatusVerbose RemoteClustersStatusVerbosity = iota
	// RemoteClustersStatusBrief outputs a one-line summary only for ready clusters.
	RemoteClustersStatusBrief
	// RemoteClustersStatusNotReadyOnly outputs the remote clusters information for non-ready clusters only.
	RemoteClustersStatusNotReadyOnly
)

func FormatStatusResponseRemoteClusters(w io.Writer, clusters []*models.RemoteCluster, verbosity RemoteClustersStatusVerbosity) {
	for _, cluster := range clusters {
		if verbosity != RemoteClustersStatusNotReadyOnly || !cluster.Ready {
			fmt.Fprintf(w, "   %s: %s, %d nodes, %d endpoints, %d identities, %d services, %d failures (last: %s)\n",
				cluster.Name, clusterReadiness(cluster), cluster.NumNodes,
				cluster.NumEndpoints, cluster.NumIdentities, cluster.NumSharedServices,
				cluster.NumFailures, timeSince(time.Time(cluster.LastFailure)))

			if verbosity == RemoteClustersStatusBrief && cluster.Ready {
				continue
			}

			fmt.Fprintf(w, "   └  %s\n", cluster.Status)

			fmt.Fprint(w, "   └  remote configuration: ")
			if cluster.Config != nil {
				fmt.Fprintf(w, "expected=%t, retrieved=%t", cluster.Config.Required, cluster.Config.Retrieved)
				if cluster.Config.Retrieved {
					fmt.Fprintf(w, ", cluster-id=%d, kvstoremesh=%t, sync-canaries=%t",
						cluster.Config.ClusterID, cluster.Config.Kvstoremesh, cluster.Config.SyncCanaries)
				}
			} else {
				fmt.Fprint(w, "expected=unknown, retrieved=unknown")
			}
			fmt.Fprint(w, "\n")

			if cluster.Synced != nil {
				fmt.Fprintf(w, "   └  synchronization status: nodes=%v, endpoints=%v, identities=%v, services=%v\n",
					cluster.Synced.Nodes, cluster.Synced.Endpoints, cluster.Synced.Identities, cluster.Synced.Services)
			}
		}
	}
}
