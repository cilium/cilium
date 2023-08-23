/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package echo

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

// MeshPod represents a connection to a specific pod running in the mesh.
// This can be used to trigger requests *from* that pod.
type MeshPod struct {
	Name      string
	Namespace string
	Address   string
	rc        rest.Interface
	rcfg      *rest.Config
}

type MeshApplication string

const (
	MeshAppEchoV1 MeshApplication = "app=echo,version=v1"
	MeshAppEchoV2 MeshApplication = "app=echo,version=v2"
)

func (m *MeshPod) MakeRequestAndExpectEventuallyConsistentResponse(t *testing.T, exp http.ExpectedResponse, timeoutConfig config.TimeoutConfig) {
	t.Helper()

	http.AwaitConvergence(t, timeoutConfig.RequiredConsecutiveSuccesses, timeoutConfig.MaxTimeToConsistency, func(elapsed time.Duration) bool {
		req := makeRequest(t, exp.Request)

		resp, err := m.request(req)
		if err != nil {
			t.Logf("Request %v failed, not ready yet: %v (after %v)", req, err.Error(), elapsed)
			return false
		}
		t.Logf("Got resp %v", resp)
		if err := compareRequest(exp, resp); err != nil {
			t.Logf("Response expectation failed for request: %v  not ready yet: %v (after %v)", req, err, elapsed)
			return false
		}
		return true
	})

	t.Logf("Request passed")
}

func makeRequest(t *testing.T, r http.Request) []string {
	protocol := strings.ToLower(r.Protocol)
	if protocol == "" {
		protocol = "http"
	}
	host := http.CalculateHost(t, r.Host, protocol)
	args := []string{"client", fmt.Sprintf("%s://%s%s", protocol, host, r.Path)}
	if r.Method != "" {
		args = append(args, "--method="+r.Method)
	}
	for k, v := range r.Headers {
		args = append(args, "-H", fmt.Sprintf("%v: %v", k, v))
	}
	return args
}

func compareRequest(exp http.ExpectedResponse, resp Response) error {
	want := exp.Response
	if fmt.Sprint(want.StatusCode) != resp.Code {
		return fmt.Errorf("wanted status code %v, got %v", want.StatusCode, resp.Code)
	}
	for _, name := range want.AbsentHeaders {
		if v := resp.ResponseHeaders.Values(name); len(v) != 0 {
			return fmt.Errorf("expected no header %q, got %v", name, v)
		}
	}
	for k, v := range want.Headers {
		if got := resp.ResponseHeaders.Get(k); got != v {
			return fmt.Errorf("expected header %v=%v, got %v", k, v, got)
		}
	}
	if !strings.HasPrefix(resp.Hostname, exp.Backend) {
		return fmt.Errorf("expected pod name to start with %s, got %s", exp.Backend, resp.Hostname)
	}
	return nil
}

func (m *MeshPod) request(args []string) (Response, error) {
	container := "echo"

	req := m.rc.Post().
		Resource("pods").
		Name(m.Name).
		Namespace(m.Namespace).
		SubResource("exec").
		Param("container", container).
		VersionedParams(&v1.PodExecOptions{
			Container: container,
			Command:   args,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(m.rcfg, "POST", req.URL())
	if err != nil {
		return Response{}, err
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
		Tty:    false,
	})
	if err != nil {
		return Response{}, err
	}

	return ParseResponse(stdoutBuf.String()), nil
}

func ConnectToApp(t *testing.T, s *suite.ConformanceTestSuite, app MeshApplication) MeshPod {
	return ConnectToAppInNamespace(t, s, app, "gateway-conformance-mesh")
}

func ConnectToAppInNamespace(t *testing.T, s *suite.ConformanceTestSuite, app MeshApplication, ns string) MeshPod {
	lbls, _ := klabels.Parse(string(app))

	podsList := v1.PodList{}
	err := s.Client.List(context.Background(), &podsList, client.InNamespace(ns), client.MatchingLabelsSelector{Selector: lbls})
	if err != nil {
		t.Fatalf("failed to query pods in app %v", app)
	}
	if len(podsList.Items) == 0 {
		t.Fatalf("no pods found in app %v", app)
	}
	pod := podsList.Items[0]
	podName := pod.Name
	podNamespace := pod.Namespace

	return MeshPod{
		Name:      podName,
		Namespace: podNamespace,
		Address:   pod.Status.PodIP,
		rc:        s.Clientset.CoreV1().RESTClient(),
		rcfg:      s.RestConfig,
	}
}
