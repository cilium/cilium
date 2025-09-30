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
	"slices"
	"strconv"
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
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
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
		req := makeRequest(t, &exp)

		resp, err := m.request(req)
		if err != nil {
			tlog.Logf(t, "Request %v failed, not ready yet: %v (after %v)", req, err.Error(), elapsed)
			return false
		}
		tlog.Logf(t, "Got resp %v", resp)
		if err := compareRequest(exp, resp); err != nil {
			tlog.Logf(t, "Response expectation failed for request: %v  not ready yet: %v (after %v)", req, err, elapsed)
			return false
		}
		return true
	})

	tlog.Logf(t, "Request passed")
}

func makeRequest(t *testing.T, exp *http.ExpectedResponse) []string {
	if exp.Request.Host == "" {
		exp.Request.Host = "echo"
	}

	r := exp.Request
	protocol := strings.ToLower(r.Protocol)
	if protocol == "" {
		protocol = "http"
	}

	// Only set default method for HTTP protocols, not for gRPC
	if protocol != "grpc" && exp.Request.Method == "" {
		exp.Request.Method = "GET"
	}

	// if the deprecated field StatusCode is set, append it to StatusCodes for backwards compatibility
	//nolint:staticcheck
	if exp.Response.StatusCode != 0 {
		exp.Response.StatusCodes = append(exp.Response.StatusCodes, exp.Response.StatusCode)
	}

	if len(exp.Response.StatusCodes) == 0 {
		exp.Response.StatusCodes = []int{200}
	}

	host := http.CalculateHost(t, r.Host, protocol)
	args := []string{"client", fmt.Sprintf("%s://%s%s", protocol, host, r.Path)}
	if protocol != "grpc" && r.Method != "" {
		args = append(args, "--method="+r.Method)
	}
	for k, v := range r.Headers {
		args = append(args, "-H", fmt.Sprintf("%v:%v", k, v))
	}
	return args
}

func compareRequest(exp http.ExpectedResponse, resp Response) error {
	if exp.ExpectedRequest == nil {
		exp.ExpectedRequest = &http.ExpectedRequest{}
	}
	wantReq := exp.ExpectedRequest
	wantResp := exp.Response

	// Parse the response status code
	statusCode, err := strconv.Atoi(resp.Code)
	if err != nil {
		return fmt.Errorf("invalid status code '%v': %v", resp.Code, err)
	}

	// Handle gRPC protocol special case for status code mapping
	if strings.ToLower(exp.Request.Protocol) == "grpc" {
		// For gRPC, we need to handle the status code mapping
		// The Istio echo client reports HTTP status codes even for gRPC requests
		expectedStatusCodes := make([]int, len(wantResp.StatusCodes))
		copy(expectedStatusCodes, wantResp.StatusCodes)

		// Map gRPC status 0 (OK) to HTTP 200 if needed
		for i, code := range expectedStatusCodes {
			if code == 0 {
				expectedStatusCodes[i] = 200
			}
		}

		if !slices.Contains(expectedStatusCodes, statusCode) {
			return fmt.Errorf("wanted gRPC status code to be one of %v (mapped to HTTP), got %d", wantResp.StatusCodes, statusCode)
		}
	} else if !slices.Contains(wantResp.StatusCodes, statusCode) {
		// For HTTP, use the status codes directly
		return fmt.Errorf("wanted status code to be one of %v, got %d", wantResp.StatusCodes, statusCode)
	}
	if wantReq.Headers != nil {
		if resp.RequestHeaders == nil {
			return fmt.Errorf("no headers captured, expected %v", len(wantReq.Headers))
		}
		for name, val := range resp.RequestHeaders {
			resp.RequestHeaders[strings.ToLower(name)] = val
		}
		for name, expectedVal := range wantReq.Headers {
			actualVal, ok := resp.RequestHeaders[strings.ToLower(name)]
			if !ok {
				return fmt.Errorf("expected %s header to be set, actual headers: %v", name, resp.RequestHeaders)
			}
			if strings.Join(actualVal, ",") != expectedVal {
				return fmt.Errorf("expected %s header to be set to %s, got %s", name, expectedVal, strings.Join(actualVal, ","))
			}
		}
	}
	if len(wantReq.AbsentHeaders) > 0 {
		for name, val := range resp.RequestHeaders {
			resp.RequestHeaders[strings.ToLower(name)] = val
		}

		for _, name := range wantReq.AbsentHeaders {
			val, ok := resp.RequestHeaders[strings.ToLower(name)]
			if ok {
				return fmt.Errorf("expected %s header to not be set, got %s", name, val)
			}
		}
	}

	for _, name := range wantResp.AbsentHeaders {
		if v := resp.ResponseHeaders.Values(name); len(v) != 0 {
			return fmt.Errorf("expected no header %q, got %v", name, v)
		}
	}
	for k, v := range wantResp.Headers {
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
		tlog.Fatalf(t, "failed to query pods in app %v", app)
	}
	if len(podsList.Items) == 0 {
		tlog.Fatalf(t, "no pods found in app %v", app)
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

func (m *MeshPod) CaptureRequestResponseAndCompare(t *testing.T, exp http.ExpectedResponse) ([]string, Response, error) {
	req := makeRequest(t, &exp)

	resp, err := m.request(req)
	if err != nil {
		tlog.Logf(t, "Request %v failed, not ready yet: %v", req, err.Error())
		return []string{}, Response{}, err
	}
	tlog.Logf(t, "Got resp %v", resp)
	if err := compareRequest(exp, resp); err != nil {
		tlog.Logf(t, "Response expectation failed for request: %v  not ready yet: %v", req, err)
		return []string{}, Response{}, err
	}
	return req, resp, nil
}
