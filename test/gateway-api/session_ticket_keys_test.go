// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	envoyadmin "github.com/envoyproxy/go-control-plane/envoy/admin/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	v1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/k8s/portforward"
	syncnames "github.com/cilium/cilium/pkg/secretsync/names"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestSessionTicketKeys(t *testing.T) {
	testutils.IntegrationTest(t)
	restConfig, err := config.GetConfig()
	require.NoError(t, err)
	testScheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(testScheme))
	require.NoError(t, v1.Install(testScheme))
	k8sClient, err := client.New(restConfig, client.Options{Scheme: testScheme})
	require.NoError(t, err)
	clientset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(t, err)
	test := sessionTicketTest{
		t:           t,
		ctx:         t.Context(),
		client:      k8sClient,
		clientset:   clientset,
		restConfig:  restConfig,
		roots:       x509.NewCertPool(),
		gatewayName: "session-ticket",
	}
	config := &corev1.ConfigMap{}
	require.NoError(t, test.client.Get(test.ctx, types.NamespacedName{
		Namespace: "kube-system", Name: "cilium-config",
	}, config))
	if interval := config.Data["gateway-api-session-ticket-rotation-interval"]; interval != "" {
		duration, err := time.ParseDuration(interval)
		require.NoError(t, err)
		require.Zero(t, duration)
	}
	test.secretNamespace = config.Data["gateway-api-secrets-namespace"]
	require.NotEmpty(t, test.secretNamespace)

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "session-ticket-e2e-"}}
	require.NoError(t, test.client.Create(test.ctx, namespace))
	test.namespace = namespace.Name
	certificate, key, err := cert.GenerateSelfSignedCertKey(sessionTicketHostname, nil, nil)
	require.NoError(t, err)
	require.True(t, test.roots.AppendCertsFromPEM(certificate))
	require.NoError(t, test.client.Create(test.ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: test.namespace, Name: "session-ticket-tls"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certificate,
			corev1.TLSPrivateKeyKey: key,
		},
	}))
	gateway := &v1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: test.namespace, Name: test.gatewayName},
		Spec: v1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []v1.Listener{{
				Name: "https", Protocol: v1.HTTPSProtocolType, Port: 443,
				Hostname: ptr.To(v1.Hostname(sessionTicketHostname)),
				TLS: &v1.ListenerTLSConfig{
					Mode: ptr.To(v1.TLSModeTerminate),
					CertificateRefs: []v1.SecretObjectReference{{
						Name: "session-ticket-tls",
					}},
				},
			}},
		},
	}
	require.NoError(t, test.client.Create(test.ctx, gateway))
	test.secretName = syncnames.GatewaySessionTicketSecretName(gateway.UID)
	test.waitForGateway()
	endpointA, endpointB, stopForwards := test.startPortForwards()

	protocols := []uint16{tls.VersionTLS12, tls.VersionTLS13}
	t.Log("disabled baseline")
	for _, version := range protocols {
		session := test.requireProbe("disabled fresh", version, endpointA, nil, false)
		test.requireProbe("disabled cross-Envoy", version, endpointB, session, false)
	}
	stopForwards()

	t.Log("enabling shared session ticket keys")
	test.setRotationInterval("2m")
	test.ticketKey = test.waitForTicketSecret(nil)
	test.waitForGateway()
	endpointA, endpointB, stopForwards = test.startPortForwards()

	t.Log("shared key cross-Envoy resumption")
	sessions := make(map[uint16]*tls.ClientSessionState)
	for _, version := range protocols {
		sessions[version] = test.requireProbe("shared fresh", version, endpointA, nil, false)
		test.requireProbe("shared same-Envoy", version, endpointA, sessions[version], true)
		test.requireProbe("shared cross-Envoy", version, endpointB, sessions[version], true)
	}

	beforeRotation := test.envoySnapshot()
	t.Log("rotating session ticket keys")
	test.ticketKey = test.waitForTicketSecret(test.ticketKey)
	test.requireProbe("rotation preserves old ticket", tls.VersionTLS12, endpointB, sessions[tls.VersionTLS12], true)
	rotatedSession := test.requireProbe("rotation fresh", tls.VersionTLS12, endpointA, nil, false)
	test.requireProbe("rotation cross-Envoy", tls.VersionTLS12, endpointB, rotatedSession, true)
	require.Equal(t, beforeRotation, test.envoySnapshot(), "Envoy pods changed during key rotation")

	t.Log("removing the previous session ticket key")
	test.ticketKey = test.waitForTicketSecret(test.ticketKey)
	test.requireProbe("removed old ticket", tls.VersionTLS12, endpointB, sessions[tls.VersionTLS12], false)
	stopForwards()

	t.Log("preserving managed keys across operator restart")
	test.setRotationInterval("1h")
	require.Equal(t, test.ticketKey, test.waitForTicketSecret(nil))

	t.Log("restarting Envoy DaemonSet")
	test.command("kubectl", "-n", "kube-system", "rollout", "restart", "daemonset/cilium-envoy")
	test.command("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/cilium-envoy", "--timeout=5m")
	_, endpointB, _ = test.startPortForwards()
	test.ticketKey = nil
	test.requireProbe("post-restart shared ticket", tls.VersionTLS12, endpointB, rotatedSession, true)

	t.Log("LoadBalancer path")
	service := &corev1.Service{}
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		require.NoError(collect, test.client.Get(test.ctx, types.NamespacedName{
			Namespace: test.namespace, Name: "cilium-gateway-" + test.gatewayName,
		}, service))
		require.NotEmpty(collect, service.Status.LoadBalancer.Ingress)
		require.NotEmpty(collect, service.Status.LoadBalancer.Ingress[0].IP)
	}, 2*time.Minute, 2*time.Second)
	endpoint := net.JoinHostPort(service.Status.LoadBalancer.Ingress[0].IP, "443")
	session := test.requireProbe("LoadBalancer fresh", tls.VersionTLS12, endpoint, nil, false)
	test.requireProbe("LoadBalancer resumed", tls.VersionTLS12, endpoint, session, true)

	t.Log("isolating tickets between Gateways with the same certificate and hostname")
	test.ticketKey = test.waitForTicketSecret(nil)
	isolatedGateway := &v1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: test.namespace, Name: "session-ticket-isolated"},
		Spec:       *gateway.Spec.DeepCopy(),
	}
	require.NoError(t, test.client.Create(test.ctx, isolatedGateway))
	isolated := test
	isolated.gatewayName = isolatedGateway.Name
	isolated.secretName = syncnames.GatewaySessionTicketSecretName(isolatedGateway.UID)
	isolated.ticketKey = isolated.waitForTicketSecret(nil)
	require.NotEqual(t, test.ticketKey, isolated.ticketKey)
	isolated.waitForGateway()
	isolatedEndpoint, _, stopIsolatedForwards := isolated.startPortForwards()
	for _, version := range protocols {
		session := test.requireProbe("isolated baseline", version, endpointB, nil, false)
		isolated.requireProbe("different Gateway rejects ticket", version, isolatedEndpoint, session, false)
	}
	stopIsolatedForwards()
}

const (
	sessionTicketHostname = "session-ticket.example.com"
	sessionTicketKey      = "tls.sessionticket.key"
)

type sessionTicketTest struct {
	t               *testing.T
	ctx             context.Context
	client          client.Client
	clientset       kubernetes.Interface
	restConfig      *rest.Config
	roots           *x509.CertPool
	namespace       string
	gatewayName     string
	secretNamespace string
	secretName      string
	ticketKey       []byte
}

func (test *sessionTicketTest) command(name string, args ...string) {
	test.t.Helper()
	ctx, cancel := context.WithTimeout(test.ctx, 5*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	test.t.Logf("%s %s:\n%s", name, strings.Join(args, " "), output)
	require.NoError(test.t, err)
}

func (test *sessionTicketTest) setRotationInterval(interval string) {
	test.t.Helper()
	chartDirectory := os.Getenv("CILIUM_HELM_CHART_DIRECTORY")
	if chartDirectory == "" {
		chartDirectory = filepath.Join("..", "..", "install", "kubernetes", "cilium")
	}
	test.command("cilium", "upgrade", "--reuse-values",
		"--chart-directory="+chartDirectory,
		"--helm-set=gatewayAPI.sessionTicketKeyRotationInterval="+interval)
	test.command("kubectl", "-n", "kube-system", "rollout", "restart", "deployment/cilium-operator")
	test.command("kubectl", "-n", "kube-system", "rollout", "status", "deployment/cilium-operator", "--timeout=5m")
	test.command("cilium", "status", "--wait", "--interactive=false")
}

func (test *sessionTicketTest) waitForGateway() {
	test.t.Helper()
	require.EventuallyWithT(test.t, func(collect *assert.CollectT) {
		gateway := &v1.Gateway{}
		require.NoError(collect, test.client.Get(test.ctx, types.NamespacedName{
			Namespace: test.namespace, Name: test.gatewayName,
		}, gateway))
		for _, conditionType := range []v1.GatewayConditionType{v1.GatewayConditionAccepted, v1.GatewayConditionProgrammed} {
			condition := meta.FindStatusCondition(gateway.Status.Conditions, string(conditionType))
			require.NotNil(collect, condition)
			require.Equal(collect, metav1.ConditionTrue, condition.Status)
			require.Equal(collect, gateway.Generation, condition.ObservedGeneration)
		}
	}, 5*time.Minute, 2*time.Second)
}

func (test *sessionTicketTest) waitForTicketSecret(previous []byte) []byte {
	test.t.Helper()
	secret := &corev1.Secret{}
	require.EventuallyWithT(test.t, func(collect *assert.CollectT) {
		require.NoError(collect, test.client.Get(test.ctx, types.NamespacedName{
			Namespace: test.secretNamespace, Name: test.secretName,
		}, secret))
		require.Equal(collect, corev1.SecretTypeOpaque, secret.Type)
		require.Len(collect, secret.Data[sessionTicketKey], 80)
		if previous != nil {
			require.Len(collect, secret.Data, 2)
			require.Equal(collect, previous, secret.Data[sessionTicketKey+".1"])
			require.NotEqual(collect, previous, secret.Data[sessionTicketKey])
		}
	}, 3*time.Minute, 2*time.Second)
	return secret.Data[sessionTicketKey]
}

func (test *sessionTicketTest) startPortForwards() (string, string, context.CancelFunc) {
	test.t.Helper()
	pods := &corev1.PodList{}
	require.NoError(test.t, test.client.List(test.ctx, pods,
		client.InNamespace("kube-system"), client.MatchingLabels{"k8s-app": "cilium-envoy"}))
	slices.SortFunc(pods.Items, func(first, second corev1.Pod) int {
		return strings.Compare(first.Name, second.Name)
	})
	var selected []corev1.Pod
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning &&
			(len(selected) == 0 || pod.Spec.NodeName != selected[0].Spec.NodeName) {
			selected = append(selected, pod)
		}
		if len(selected) == 2 {
			break
		}
	}
	require.Len(test.t, selected, 2, "need two running Envoy pods on different nodes")
	ctx, cancel := context.WithCancel(test.ctx)
	test.t.Cleanup(cancel)
	var endpoints []string
	for _, pod := range selected {
		port := test.listenerPort(pod.Spec.NodeName)
		forward, err := portforward.NewPortForwarder(test.clientset, test.restConfig).
			PortForward(ctx, portforward.PortForwardParameters{
				Namespace: "kube-system", Pod: pod.Name,
				Ports: []string{fmt.Sprintf("0:%d", port)}, Addresses: []string{"127.0.0.1"},
			})
		require.NoError(test.t, err)
		require.Len(test.t, forward.ForwardedPorts, 1)
		endpoints = append(endpoints, fmt.Sprintf("127.0.0.1:%d", forward.ForwardedPorts[0].Local))
		test.t.Logf("Forwarding %s on node %s: %s -> %d", pod.Name, pod.Spec.NodeName, endpoints[len(endpoints)-1], port)
	}
	return endpoints[0], endpoints[1], cancel
}

func (test *sessionTicketTest) listenerPort(node string) uint32 {
	test.t.Helper()
	agents := &corev1.PodList{}
	require.NoError(test.t, test.client.List(test.ctx, agents,
		client.InNamespace("kube-system"), client.MatchingLabels{"k8s-app": "cilium"},
		client.MatchingFields{"spec.nodeName": node}))
	require.Len(test.t, agents.Items, 1)
	request := test.clientset.CoreV1().RESTClient().Post().Namespace("kube-system").
		Resource("pods").Name(agents.Items[0].Name).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
		Container: "cilium-agent",
		Command:   []string{"cilium-dbg", "envoy", "admin", "listeners", "-o", "json"},
		Stdout:    true, Stderr: true,
	}, scheme.ParameterCodec)
	var port uint32
	require.EventuallyWithT(test.t, func(collect *assert.CollectT) {
		executor, err := remotecommand.NewSPDYExecutor(test.restConfig, http.MethodPost, request.URL())
		require.NoError(collect, err)
		ctx, cancel := context.WithTimeout(test.ctx, 20*time.Second)
		defer cancel()
		var stdout, stderr bytes.Buffer
		err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr})
		require.NoError(collect, err, stderr.String())
		listeners := &envoyadmin.Listeners{}
		require.NoError(collect, protojson.Unmarshal(stdout.Bytes(), listeners))
		for _, listener := range listeners.ListenerStatuses {
			if strings.HasPrefix(listener.Name, test.namespace+"/cilium-gateway-"+test.gatewayName+"/") {
				port = listener.GetLocalAddress().GetSocketAddress().GetPortValue()
				break
			}
		}
		require.NotZero(collect, port, "Gateway listener not active on node %s", node)
	}, 3*time.Minute, 2*time.Second)
	return port
}

func (test *sessionTicketTest) envoySnapshot() map[types.UID]int32 {
	test.t.Helper()
	pods := &corev1.PodList{}
	require.NoError(test.t, test.client.List(test.ctx, pods,
		client.InNamespace("kube-system"), client.MatchingLabels{"k8s-app": "cilium-envoy"}))
	snapshot := make(map[types.UID]int32)
	for _, pod := range pods.Items {
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == "cilium-envoy" {
				snapshot[pod.UID] = status.RestartCount
			}
		}
	}
	return snapshot
}

func (test *sessionTicketTest) requireProbe(label string, version uint16, endpoint string,
	session *tls.ClientSessionState, wantResume bool) *tls.ClientSessionState {
	test.t.Helper()
	var ticket *tls.ClientSessionState
	require.EventuallyWithT(test.t, func(collect *assert.CollectT) {
		state, resumed, err := probeTLSSession(test.ctx, test.roots, endpoint, version, session)
		require.NoError(collect, err)
		require.Equal(collect, wantResume, resumed, "%s: %s on %s", label, tls.VersionName(version), endpoint)
		require.NotNil(collect, state, "server did not issue a session ticket")
		if test.ticketKey != nil {
			identity, _, err := state.ResumptionState()
			require.NoError(collect, err)
			require.GreaterOrEqual(collect, len(identity), 16)
			require.Equal(collect, test.ticketKey[:16], identity[:16], "Envoy has not applied the current ticket key")
		}
		ticket = state
	}, 3*time.Minute, 2*time.Second, "%s: %s", label, tls.VersionName(version))
	test.t.Logf("%s: %s on %s, resumed=%t", label, tls.VersionName(version), endpoint, wantResume)
	return ticket
}

func probeTLSSession(ctx context.Context, roots *x509.CertPool, endpoint string, version uint16,
	session *tls.ClientSessionState) (*tls.ClientSessionState, bool, error) {
	cache := tls.NewLRUClientSessionCache(1)
	if session != nil {
		cache.Put(sessionTicketHostname, session)
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 20 * time.Second},
		Config: &tls.Config{
			RootCAs: roots, ServerName: sessionTicketHostname,
			MinVersion: version, MaxVersion: version, ClientSessionCache: cache,
		},
	}
	connection, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, false, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return nil, false, err
	}
	if _, err := fmt.Fprintf(connection, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sessionTicketHostname); err != nil {
		return nil, false, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodHead})
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, connection); err != nil {
		return nil, false, err
	}
	state, _ := cache.Get(sessionTicketHostname)
	return state, connection.(*tls.Conn).ConnectionState().DidResume, nil
}
