// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"text/template"

	"github.com/cilium/cilium/pkg/time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
)

const (
	frrDaemonSetNameName = "frr-external-node"
	frrConfigMapName     = "frr-config"

	frrBaseConfig = `
log stdout debugging
debug bgp zebra
debug bgp neighbor-events
debug bgp updates
`

	frrBGPPeeringTemplate = `
router bgp {{ .LocalASN }}
  no bgp ebgp-requires-policy
  bgp default ipv6-unicast
  neighbor CILIUM peer-group
  neighbor CILIUM remote-as external
{{- range $peer := .Peers }}
  neighbor {{$peer}} peer-group CILIUM
{{- end }}
exit
`
)

// FRRBGPPeeringParams holds information for rendering FRR BGP peering configuration.
type FRRBGPPeeringParams struct {
	LocalASN int
	Peers    []netip.Addr
}

// FRRBGPNeighborInfo holds FRR BGP neighbor information equivalent to "show bgp neighbor json" CLI output entry.
type FRRBGPNeighborInfo struct {
	RemoteAS       int    `json:"remoteAs"`
	LocalAS        int    `json:"localAs"`
	Hostname       string `json:"hostname"`
	RemoteRouterID string `json:"remoteRouterId"`
	LocalRouterID  string `json:"localRouterId"`
	BGPState       string `json:"bgpState"`
}

// FRRBGPPrefixMap is a map of BGP route information indexed by prefix.
type FRRBGPPrefixMap map[string][]FRRBGPRouteInfo

// FRRBGPAddressFamilyInfo holds FRR BGP address family information
// equivalent to "show bgp <family> detail json" CLI output entry.
type FRRBGPAddressFamilyInfo struct {
	VrfID    int             `json:"vrfId"`
	VrfName  string          `json:"vrfName"`
	RouterID string          `json:"routerId"`
	LocalAS  int             `json:"localAS"`
	Routes   FRRBGPPrefixMap `json:"routes"`
}

// FRRBGPRouteInfo holds information about a BGP route,
// as it can be retried from the "show bgp <family> detail json" CLI output.
type FRRBGPRouteInfo struct {
	Origin   string `json:"origin"`
	Valid    bool   `json:"valid"`
	Version  int    `json:"version"`
	BestPath struct {
		Overall         bool   `json:"overall"`
		SelectionReason string `json:"selectionReason"`
	} `json:"bestpath"`
	ASPath struct {
		String   string `json:"string"`
		Segments []struct {
			Type string `json:"type"`
			List []int  `json:"list"`
		} `json:"segments"`
		Length int `json:"length"`
	} `json:"aspath"`
	Community struct {
		String string   `json:"string"`
		List   []string `json:"list"`
	} `json:"community"`
	NextHops []FRRBGPNextHopInfo `json:"nexthops"`
}

// FRRBGPNextHopInfo holds next hop information of a BGP route,
// as it can be retried from the "show bgp <family> detail json" CLI output.
type FRRBGPNextHopInfo struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	Afi        string `json:"afi"`
	Scope      string `json:"scope"`
	Metric     int    `json:"metric"`
	Accessible bool   `json:"accessible"`
	Used       bool   `json:"used"`
}

// NewFRRDaemonSet returns a k8s DaemonSet with FRR, configured to run on "nodes without cilium".
func NewFRRDaemonSet(params Parameters) *appsv1.DaemonSet {
	ds := newDaemonSet(daemonSetParameters{
		Name:         frrDaemonSetNameName,
		Kind:         frrDaemonSetNameName,
		Image:        params.FRRImage,
		Labels:       map[string]string{"external": "frr"},
		NodeSelector: map[string]string{"cilium.io/no-schedule": "true"},
		HostNetwork:  true,
		Tolerations: []corev1.Toleration{
			{Operator: corev1.TolerationOpExists},
		},
		Capabilities: []corev1.Capability{"NET_ADMIN", "NET_RAW", "SYS_ADMIN"},
	})
	ds.Spec.Template.Spec.TerminationGracePeriodSeconds = ptr.To[int64](0)
	ds.Spec.Template.Spec.Volumes = []corev1.Volume{
		{
			Name: frrConfigMapName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: frrConfigMapName,
					},
				},
			},
		},
	}
	ds.Spec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
		{
			Name:      frrConfigMapName,
			SubPath:   "daemons",
			MountPath: "/etc/frr/daemons",
		},
		{
			Name:      frrConfigMapName,
			SubPath:   "vtysh.conf",
			MountPath: "/etc/frr/vtysh.conf",
		},
	}
	return ds
}

// NewFRRConfigMap returns a k8s ConfigMap used by the FRR DaemonSet, containing FRR daemon configuration.
func NewFRRConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: frrConfigMapName,
		},
		Data: map[string]string{
			"vtysh.conf": "service integrated-vtysh-config",
			"daemons": `
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=yes
fabricd=no
vrrpd=no
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
bgpd_options="   -A 127.0.0.1"
ospfd_options="  -A 127.0.0.1"
ospf6d_options=" -A ::1"
ripd_options="   -A 127.0.0.1"
ripngd_options=" -A ::1"
isisd_options="  -A 127.0.0.1"
pimd_options="   -A 127.0.0.1"
ldpd_options="   -A 127.0.0.1"
nhrpd_options="  -A 127.0.0.1"
eigrpd_options=" -A 127.0.0.1"
babeld_options=" -A 127.0.0.1"
sharpd_options=" -A 127.0.0.1"
pbrd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
bfdd_options="   -A 127.0.0.1"
fabricd_options="-A 127.0.0.1"
vrrpd_options="  -A 127.0.0.1"
MAX_FDS=1024
`,
		},
	}
}

// RunFRRCommand runs a CLI command on the given FRR pod.
func RunFRRCommand(ctx context.Context, t *Test, frrPod *Pod, cmd string) []byte {
	cmdArr := []string{"vtysh", "-c", cmd}
	stdout, stderr, err := frrPod.K8sClient.ExecInPodWithStderr(ctx,
		frrPod.Pod.Namespace, frrPod.Pod.Name, frrPod.Pod.Labels["name"], cmdArr)
	if err != nil || stderr.String() != "" {
		t.Fatalf("failed to run FRR command: %v: %s", err, stderr.String())
	}
	return stdout.Bytes()
}

// ApplyFRRConfig applies provided CLI configuration on the given FRR pod
// by replacing its existing config. Base FRR config is applied along with the provided one.
func ApplyFRRConfig(ctx context.Context, t *Test, frrPod *Pod, config string) {
	err := writeDataToPod(ctx, frrPod, "/etc/frr/frr.conf", []byte(frrBaseConfig+config))
	if err != nil {
		t.Fatalf("failed writing config to FRR: %v", err)
	}
	_, stderr, err := frrPod.K8sClient.ExecInPodWithStderr(ctx,
		frrPod.Pod.Namespace, frrPod.Pod.Name, frrPod.Pod.Labels["name"], []string{"/usr/lib/frr/frr-reload"})
	if err != nil { // do not check stderr - contains logs upon successful reload aas well
		t.Fatalf("failed reloading FRR config: %v: %s", err, stderr.String())
	}
}

// ClearFRRConfig clears configuration on the given FRR pod. Only base config remains applied.
func ClearFRRConfig(ctx context.Context, t *Test, frrPod *Pod) {
	ApplyFRRConfig(ctx, t, frrPod, "")
}

// RenderFRRBGPPeeringConfig renders standard BGP peering configuration for provided list of
// peer addresses. The returned config can be used to apply in an FRR pod.
func RenderFRRBGPPeeringConfig(t *Test, params FRRBGPPeeringParams) string {
	var config bytes.Buffer
	tpl, err := template.New("").Parse(frrBGPPeeringTemplate)
	if err != nil {
		t.Fatalf("failed to parse FRR config template: %v", err)
	}
	err = tpl.Execute(&config, params)
	if err != nil {
		t.Fatalf("failed to render FRR config template: %v", err)
	}
	return config.String()
}

// WaitForFRRBGPNeighborsState waits until provided list of BGP peers reach the provided state
// on the provided FRR pod.
func WaitForFRRBGPNeighborsState(ctx context.Context, t *Test, frrPod *Pod, expPeers []netip.Addr, expState string) {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 30 * time.Second})
	defer w.Cancel()

	ensureBGPNeighborsState := func() error {
		stdout := RunFRRCommand(ctx, t, frrPod, "show bgp neighbor json")
		entries := map[string]FRRBGPNeighborInfo{}
		err := json.Unmarshal(stdout, &entries)
		if err != nil {
			return err
		}
		if len(entries) < len(expPeers) {
			return fmt.Errorf("expected %d peers, got %d", len(expPeers), len(entries))
		}
		for _, peer := range expPeers {
			frrPeer, exists := entries[peer.String()]
			if !exists {
				return fmt.Errorf("missing peer %s", peer.String())
			}
			if frrPeer.BGPState != expState {
				return fmt.Errorf("peer %s: expected %s state, got %s", peer, expState, entries[peer.String()].BGPState)
			}
		}
		return nil
	}

	for {
		if err := ensureBGPNeighborsState(); err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatalf("Failed to ensure FRR BGP neighbor states: %v", err)
			}
			continue
		}
		return
	}
}

// WaitForFRRBGPPrefixes waits until the provided prefixes are learned via BGP on the provided FRR pod
// and returns detailed information about all learned prefixes.
func WaitForFRRBGPPrefixes(ctx context.Context, t *Test, frrPod *Pod, expPrefixes []netip.Prefix, ipFamily features.IPFamily) FRRBGPPrefixMap {
	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 15 * time.Second})
	defer w.Cancel()

	ensureBGPNeighborsState := func() (FRRBGPPrefixMap, error) {
		cmd := "show bgp ipv4 detail json"
		if ipFamily == features.IPFamilyV6 {
			cmd = "show bgp ipv6 detail json"
		}
		stdout := RunFRRCommand(ctx, t, frrPod, cmd)
		entries := FRRBGPAddressFamilyInfo{}
		err := json.Unmarshal(stdout, &entries)
		if err != nil {
			return nil, err
		}
		if len(entries.Routes) < len(expPrefixes) {
			return nil, fmt.Errorf("expected %d prefixes, got %d", len(expPrefixes), len(entries.Routes))
		}
		for _, prefix := range expPrefixes {
			if _, exists := entries.Routes[prefix.String()]; !exists {
				return nil, fmt.Errorf("prefix %s missing on FFR", prefix.String())
			}
		}
		return entries.Routes, nil
	}

	for {
		frrPrefixes, err := ensureBGPNeighborsState()
		if err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatalf("Failed to ensure FRR BGP prefixes: %v", err)
			}
			continue
		}
		return frrPrefixes
	}
}

// AssertFRRBGPCommunity asserts that provided BGP community is present in provided FRR BGP prefixes
// filtered by checkPrefixes list.
func AssertFRRBGPCommunity(t *Test, frrPrefixes FRRBGPPrefixMap, checkPrefixes []netip.Prefix, expectedCommunity string) {
	for _, prefix := range checkPrefixes {
		for _, frrPrefix := range frrPrefixes[prefix.String()] {
			if frrPrefix.Community.String != expectedCommunity {
				t.Fatalf("prefix %s: expected community '%s', got '%s'", prefix.String(), expectedCommunity, frrPrefix.Community.String)
			}
		}
	}
}

// DumpFRRBGPState dumps FRR's BGP state into the log.
func DumpFRRBGPState(ctx context.Context, t *Test, frrPod *Pod) {
	t.Logf("FRR %s state:", frrPod.Name())
	t.Logf("%s", RunFRRCommand(ctx, t, frrPod, "show bgp neighbors"))
	t.Logf("%s", RunFRRCommand(ctx, t, frrPod, "show bgp ipv4 detail"))
	t.Logf("%s", RunFRRCommand(ctx, t, frrPod, "show bgp ipv6 detail"))
}

func writeDataToPod(ctx context.Context, pod *Pod, filePath string, data []byte) error {
	encodedData := base64.StdEncoding.EncodeToString(data)
	_, stderr, err := pod.K8sClient.ExecInPodWithStderr(ctx,
		pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"],
		[]string{"sh", "-c", fmt.Sprintf("echo %s | base64 -d > %s", encodedData, filePath)})

	if err != nil || stderr.String() != "" {
		return fmt.Errorf("failed writing data to pod: %s: %s", err, stderr.String())
	}
	return nil
}
