// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/blang/semver/v4"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/stretchr/testify/assert"
	"gopkg.in/check.v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type SysdumpSuite struct{}

var _ = check.Suite(&SysdumpSuite{})

func (b *SysdumpSuite) TestSysdumpCollector(c *check.C) {
	client := fakeClient{
		nodeList: &corev1.NodeList{
			Items: []corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}},
			},
		},
	}
	options := Options{
		OutputFileName: "my-sysdump-<ts>",
		Writer:         io.Discard,
	}
	startTime := time.Unix(946713600, 0)
	timestamp := startTime.Format(timeFormat)
	collector, err := NewCollector(&client, options, startTime, "cilium-cli-version")
	c.Assert(err, check.IsNil)
	c.Assert(path.Base(collector.sysdumpDir), check.Equals, "my-sysdump-"+timestamp)
	tempFile := collector.AbsoluteTempPath("my-file-<ts>")
	c.Assert(tempFile, check.Equals, path.Join(collector.sysdumpDir, "my-file-"+timestamp))
	_, err = os.Stat(path.Join(collector.sysdumpDir, sysdumpLogFile))
	c.Assert(err, check.IsNil)
}

func (b *SysdumpSuite) TestNodeList(c *check.C) {
	options := Options{
		Writer: io.Discard,
	}
	client := fakeClient{
		nodeList: &corev1.NodeList{
			Items: []corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "node-c"}},
			},
		},
	}
	collector, err := NewCollector(&client, options, time.Now(), "cilium-cli-version")
	c.Assert(err, check.IsNil)
	c.Assert(collector.NodeList, check.DeepEquals, []string{"node-a", "node-b", "node-c"})

	options = Options{
		Writer:   io.Discard,
		NodeList: "node-a,node-c",
	}
	collector, err = NewCollector(&client, options, time.Now(), "cilium-cli-version")
	c.Assert(err, check.IsNil)
	c.Assert(collector.NodeList, check.DeepEquals, []string{"node-a", "node-c"})
}

func (b *SysdumpSuite) TestAddTasks(c *check.C) {
	options := Options{
		Writer: io.Discard,
	}
	client := fakeClient{
		nodeList: &corev1.NodeList{
			Items: []corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}},
			},
		},
	}
	collector, err := NewCollector(&client, options, time.Now(), "cilium-cli-version")
	c.Assert(err, check.IsNil)
	collector.AddTasks([]Task{{}, {}, {}})
	c.Assert(len(collector.additionalTasks), check.Equals, 3)
	collector.AddTasks([]Task{{}, {}, {}})
	c.Assert(len(collector.additionalTasks), check.Equals, 6)
}

func (b *SysdumpSuite) TestExtractGopsPID(c *check.C) {
	var pid string
	var err error

	normalOutput := `
25863 0     gops          unknown Go version /usr/bin/gops
25852 25847 cilium        unknown Go version /usr/bin/cilium
10    1     cilium-agent* unknown Go version /usr/bin/cilium-agent
1     0     custom        go1.16.3           /usr/local/bin/custom
	`
	pid, err = extractGopsPID(normalOutput)
	c.Assert(err, check.IsNil)
	c.Assert(pid, check.Equals, "10")

	missingAgent := `
25863 0     gops          unknown Go version /usr/bin/gops
25852 25847 cilium        unknown Go version /usr/bin/cilium
10    1     cilium-agent unknown Go version /usr/bin/cilium-agent
1     0     custom        go1.16.3           /usr/local/bin/custom
	`
	pid, err = extractGopsPID(missingAgent)
	c.Assert(err, check.NotNil)
	c.Assert(pid, check.Equals, "")

	multipleAgents := `
25863 0     gops*          unknown Go version /usr/bin/gops
25852 25847 cilium*        unknown Go version /usr/bin/cilium
10    1     cilium-agent unknown Go version /usr/bin/cilium-agent
1     0     custom        go1.16.3           /usr/local/bin/custom
	`
	pid, err = extractGopsPID(multipleAgents)
	c.Assert(err, check.IsNil)
	c.Assert(pid, check.Equals, "25863")

	noOutput := ``
	_, err = extractGopsPID(noOutput)
	c.Assert(err, check.NotNil)

}

func (b *SysdumpSuite) TestExtractGopsProfileData(c *check.C) {
	gopsOutput := `
	Profiling CPU now, will take 30 secs...
	Profile dump saved to: /tmp/cpu_profile3302111893
	`
	wantFilepath := "/tmp/cpu_profile3302111893"

	gotFilepath, err := extractGopsProfileData(gopsOutput)
	c.Assert(err, check.IsNil)
	c.Assert(gotFilepath, check.Equals, wantFilepath)

}

func TestKVStoreTask(t *testing.T) {
	assert := assert.New(t)
	client := &fakeClient{
		nodeList: &corev1.NodeList{
			Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}},
		},
		execs: make(map[execRequest]execResult),
	}
	addKVStoreGet := func(c *fakeClient, ciliumPaths ...string) {
		for _, path := range ciliumPaths {
			c.expectExec("ns0", "pod0", defaults.AgentContainerName,
				[]string{"cilium", "kvstore", "get", "cilium/" + path, "--recursive", "-o", "json"},
				[]byte("{}"), nil, nil)
		}
	}
	addKVStoreGet(client, "state/identities", "state/ip", "state/nodes", "state/cnpstatuses", ".heartbeat", "state/services")
	options := Options{
		OutputFileName: "my-sysdump-<ts>",
		Writer:         io.Discard,
	}
	collector, err := NewCollector(client, options, time.Now(), "cilium-cli-version")
	assert.NoError(err)
	collector.submitKVStoreTasks(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod0",
			Namespace: "ns0",
		},
	})
	fd, err := os.Open(path.Join(collector.sysdumpDir, "kvstore-heartbeat.json"))
	assert.NoError(err)
	data, err := io.ReadAll(fd)
	assert.NoError(err)
	assert.Equal([]byte("{}"), data)
}

type execRequest struct {
	namespace string
	pod       string
	container string
	command   string
}

type execResult struct {
	stderr []byte
	stdout []byte
	err    error
}

type fakeClient struct {
	nodeList *corev1.NodeList
	execs    map[execRequest]execResult
}

func (c *fakeClient) ListCiliumBGPPeeringPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumBGPPeeringPolicyList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumLoadBalancerIPPools(ctx context.Context, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumLoadBalancerIPPoolList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumNodeConfigs(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2alpha1.CiliumNodeConfigList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumClusterwideEnvoyConfigs(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideEnvoyConfigList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumEnvoyConfigs(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEnvoyConfigList, error) {
	panic("implement me")
}

func (c *fakeClient) ListIngresses(ctx context.Context, o metav1.ListOptions) (*networkingv1.IngressList, error) {
	panic("implement me")
}

func (c *fakeClient) CopyFromPod(ctx context.Context, namespace, pod, container, fromFile, destFile string, retryLimit int) error {
	panic("implement me")
}

func (c *fakeClient) AutodetectFlavor(ctx context.Context) k8s.Flavor {
	panic("implement me")
}

func (c *fakeClient) GetPod(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Pod, error) {
	panic("implement me")
}

func (c *fakeClient) CreatePod(ctx context.Context, namespace string, pod *corev1.Pod, opts metav1.CreateOptions) (*corev1.Pod, error) {
	panic("implement me")
}

func (c *fakeClient) DeletePod(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	panic("implement me")
}

func (c *fakeClient) expectExec(namespace, pod, container string, command []string, expectedStdout []byte, expectedStderr []byte, expectedErr error) {
	r := execRequest{namespace, pod, container, strings.Join(command, " ")}
	c.execs[r] = execResult{
		stdout: expectedStdout,
		stderr: expectedStderr,
		err:    expectedErr,
	}
}

func (c *fakeClient) ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error) {
	stdout, _, err := c.ExecInPodWithStderr(ctx, namespace, pod, container, command)
	return stdout, err
}

func (c *fakeClient) ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	r := execRequest{namespace, pod, container, strings.Join(command, " ")}
	out, ok := c.execs[r]
	if !ok {
		panic(fmt.Sprintf("unexpected exec: %v", r))
	}
	return *bytes.NewBuffer(out.stdout), *bytes.NewBuffer(out.stderr), out.err
}

func (c *fakeClient) GetCiliumVersion(ctx context.Context, p *corev1.Pod) (*semver.Version, error) {
	panic("implement me")
}

func (c *fakeClient) GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error) {
	panic("implement me")
}

func (c *fakeClient) GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error) {
	return nil, nil
}

func (c *fakeClient) GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error) {
	return nil, nil
}

func (c *fakeClient) GetLogs(ctx context.Context, namespace, name, container string, sinceTime time.Time, limitBytes int64, previous bool) (string, error) {
	panic("implement me")
}

func (c *fakeClient) GetPodsTable(ctx context.Context) (*metav1.Table, error) {
	panic("implement me")
}

func (c *fakeClient) GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	panic("implement me")
}

func (c *fakeClient) GetVersion(ctx context.Context) (string, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumClusterwideNetworkPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumIdentities(ctx context.Context) (*ciliumv2.CiliumIdentityList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumEgressGatewayPolicies(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumEgressGatewayPolicyList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumEndpoints(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumLocalRedirectPolicies(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumLocalRedirectPolicyList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumNetworkPolicies(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumNetworkPolicyList, error) {
	panic("implement me")
}

func (c *fakeClient) ListCiliumNodes(ctx context.Context) (*ciliumv2.CiliumNodeList, error) {
	panic("implement me")
}

func (c *fakeClient) ListDaemonSet(ctx context.Context, namespace string, o metav1.ListOptions) (*appsv1.DaemonSetList, error) {
	panic("implement me")
}

func (c *fakeClient) ListEvents(ctx context.Context, o metav1.ListOptions) (*corev1.EventList, error) {
	panic("implement me")
}

func (c *fakeClient) ListNamespaces(ctx context.Context, o metav1.ListOptions) (*corev1.NamespaceList, error) {
	panic("implement me")
}

func (c *fakeClient) ListEndpoints(ctx context.Context, o metav1.ListOptions) (*corev1.EndpointsList, error) {
	panic("implement me")
}

func (c *fakeClient) ListNetworkPolicies(ctx context.Context, o metav1.ListOptions) (*networkingv1.NetworkPolicyList, error) {
	panic("implement me")
}

func (c *fakeClient) ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error) {
	return c.nodeList, nil
}

func (c *fakeClient) ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error) {
	panic("implement me")
}

func (c *fakeClient) ListServices(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.ServiceList, error) {
	panic("implement me")
}

func (c *fakeClient) ListUnstructured(ctx context.Context, gvr schema.GroupVersionResource, namespace *string, o metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	panic("implement me")
}

func (c *fakeClient) CreateEphemeralContainer(ctx context.Context, pod *corev1.Pod, container *corev1.EphemeralContainer) (*corev1.Pod, error) {
	panic("implement me")
}

func (c *fakeClient) GetNamespace(_ context.Context, ns string, _ metav1.GetOptions) (*corev1.Namespace, error) {
	if ns == "kube-system" {
		return &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: ns,
			},
		}, nil
	}
	return nil, &errors.StatusError{
		ErrStatus: metav1.Status{
			Code: http.StatusNotFound,
		},
	}
}
