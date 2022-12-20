// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToPodEncryption is a test case which checks the following:
//   - There is a connectivity between pods on different nodes when any
//     encryption mode is on (either WireGuard or IPsec).
//   - No unencrypted packet is leaked.
//
// The checks are implemented by curl'ing a server pod from a client pod, and
// then inspecting tcpdump captures from the client pod's node.
func PodToPodEncryption() check.Scenario {
	return &podToPodEncryption{}
}

type podToPodEncryption struct{}

func (s *podToPodEncryption) Name() string {
	return "pod-to-pod-encryption"
}

func (s *podToPodEncryption) Run(ctx context.Context, t *check.Test) {
	client := t.Context().RandomClientPod()

	var server check.Pod
	for _, pod := range t.Context().EchoPods() {
		// Make sure that the server pod is on another node than client
		if pod.Pod.Status.HostIP != client.Pod.Status.HostIP {
			server = pod
			break
		}
	}

	// clientHost is a pod running on the same node as the client pod, just in
	// the host netns.
	clientHost := t.Context().HostNetNSPodsByNode()[client.Pod.Spec.NodeName]

	// Determine on which netdev iface to capture pkts. In the case of tunneling,
	// we don't expect to see unencrypted pkts on a corresponding tunneling iface,
	// so the choice is obvious. In the native routing mode, we run
	// "ip route get $SERVER_POD_IP" from the client pod's node.
	iface := ""
	tunnelFeat, ok := t.Context().Feature(check.FeatureTunnel)
	if ok && tunnelFeat.Enabled {
		iface = "cilium_" + tunnelFeat.Mode // E.g. cilium_vxlan
	} else {
		cmd := []string{"/bin/sh", "-c",
			fmt.Sprintf("ip -o r g %s | grep -oE 'dev [^ ]*' | cut -d' ' -f2",
				server.Pod.Status.PodIP)}
		t.Debugf("Running %s", strings.Join(cmd, " "))
		dev, err := clientHost.K8sClient.ExecInPod(ctx, clientHost.Pod.Namespace,
			clientHost.Pod.Name, "", cmd)
		if err != nil {
			t.Fatalf("Failed to get IP route: %s", err)
		}
		iface = strings.TrimRight(dev.String(), "\n\r")
	}

	t.Debugf("Detected %s iface for communication among client and server nodes",
		iface)

	bgStdout := &safeBuffer{}
	bgStderr := &safeBuffer{}
	bgExited := make(chan struct{})
	killCmdCtx, killCmd := context.WithCancel(context.Background())
	// Start kubectl exec in bg (=goroutine)
	go func() {
		// Run tcpdump with -w instead of directly printing captured pkts. This
		// is to avoid a race after sending ^C (triggered by bgCancel()) which
		// might terminate the tcpdump process before it gets a chance to dump
		// its captures.
		cmd := []string{
			"tcpdump", "-i", iface, "--immediate-mode", "-w", "/tmp/foo.pcap",
			// Capture pod egress traffic.
			// Unfortunately, we cannot use "host %s and host %s" filter here,
			// as IPsec recirculates replies to the iface netdev, which would
			// make tcpdump to capture the pkts (false positive).
			fmt.Sprintf("src host %s and dst host %s", client.Pod.Status.PodIP, server.Pod.Status.PodIP),
			// Only one pkt is enough, as we don't expect any unencrypted pkt
			// to be captured
			"-c", "1"}
		t.Debugf("Running in bg: %s", strings.Join(cmd, " "))
		err := clientHost.K8sClient.ExecInPodWithWriters(ctx, killCmdCtx,
			clientHost.Pod.Namespace, clientHost.Pod.Name, "", cmd, bgStdout, bgStderr)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Failed to execute tcpdump: %s", err)
		}
		close(bgExited)
	}()

	// Wait until tcpdump is ready to capture pkts
	timeout := time.After(5 * time.Second)
	for found := false; !found; {
		select {
		case <-timeout:
			t.Fatalf("Failed to wait for tcpdump to be ready")
		default:
			line, err := bgStdout.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("Failed to read kubectl exec's stdout: %s", err)
			}
			if strings.Contains(line, fmt.Sprintf("listening on %s", iface)) {
				found = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Curl the server from the client to generate some traffic
	t.NewAction(s, "curl", client, server).Run(func(a *check.Action) {
		a.ExecInPod(ctx, curl(server))
	})

	// Wait until tcpdump has exited
	killCmd()
	<-bgExited

	// Redirect stderr to /dev/null, as tcpdump logs to stderr, and ExecInPod
	// will return an error if any char is written to stderr. Anyway, the count
	// is written to stdout.
	cmd := []string{"/bin/sh", "-c", "tcpdump -r /tmp/foo.pcap --count 2>/dev/null"}
	count, err := clientHost.K8sClient.ExecInPod(ctx, clientHost.Pod.Namespace, clientHost.Pod.Name, "", cmd)
	if err != nil {
		t.Fatalf("Failed to retrieve tcpdump pkt count: %s", err)
	}
	if !strings.HasPrefix(count.String(), "0 packets") {
		t.Fatalf("Captured unencrypted pkt (count=%s)", count.String())
	}
}

// bytes.Buffer from the stdlib is non-thread safe, thus our custom
// implementation. Unfortunately, we cannot use io.Pipe, as Write() blocks until
// Read() has read all content, which makes it deadlock-prone when used with
// ExecInPodWithWriters() running in a separate goroutine.
type safeBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *safeBuffer) Read(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Read(p)
}

func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Write(p)
}

func (b *safeBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.b.String()
}

func (b *safeBuffer) ReadString(d byte) (string, error) {
	b.Lock()
	defer b.Unlock()
	return b.b.ReadString(d)
}
