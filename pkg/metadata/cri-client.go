package metadata

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	runtimeapiV1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

const (
	// maxMsgSize use 16MB as the default message size limit.
	// grpc library default is 4MB
	maxMsgSize     = 1024 * 1024 * 16
	defaultTimeout = 2 * time.Second
)

var (
	// List of default endpoints for container runtimes.
	defaultRuntimeEndpoints = []string{"unix:///var/run/dockershim.sock", "unix:///run/containerd/containerd.sock", "unix:///run/crio/crio.sock", "unix:///var/run/cri-dockerd.sock"}
)

type runtimeClient struct {
	timeout               time.Duration
	runtimeClient         runtimeapi.RuntimeServiceClient
	runtimeClientV1alpha2 runtimeapiV1alpha2.RuntimeServiceClient
	ctx                   context.Context
	ctxCancel             context.CancelFunc
	v1API                 bool
}

var remoteRuntimeClient *runtimeClient

func initCRIClient() {
	// TODO: Read the exact endpoint from /etc/crictl.yaml if present. However,
	//  agent may not have access to the file on the host, so it would've to be mounted.
	for _, endPoint := range defaultRuntimeEndpoints {
		log.Debugf("Connect using endpoint %q with %q timeout", endPoint, defaultTimeout)

		if err := newRemoteRuntimeClient(endPoint, defaultTimeout); err != nil {
			continue
		}

		log.Debugf("Connected successfully to endpoint: %s", endPoint)
		break
	}
}

// TODO
func FiniCRIClient() {
	if remoteRuntimeClient != nil {
		remoteRuntimeClient.ctxCancel()
	}
}

func newRemoteRuntimeClient(endpoint string, timeout time.Duration) error {
	addr, dialer, err := GetAddressAndDialer(endpoint)
	if err != nil {
		log.Errorf("Failed to parse endpoint (%s): %v", endpoint, err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(), grpc.WithContextDialer(dialer), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)))
	if err != nil {
		log.Errorf("Failed to connect to remote runtime (%s): %v", addr, err)
		return err
	}

	remoteRuntimeClient = &runtimeClient{
		timeout:   timeout,
		ctx:       ctx,
		ctxCancel: cancel,
		v1API:     false,
	}

	if err := remoteRuntimeClient.determineAPIVersion(conn); err != nil {
		return err
	}

	return nil
}

// The following code is adapted from k8s.io/kubernetes/pkg/kubelet/cri/remote/remote_runtime.go.

// determineAPIVersion tries to connect to the remote runtime by using the
// highest available API version.
//
// A GRPC redial will always use the initially selected (or automatically
// determined) CRI API version. If the redial was due to the container runtime
// being upgraded, then the container runtime must also support the initially
// selected version or the redial is expected to fail, which requires a restart
// of kubelet.
func (r *runtimeClient) determineAPIVersion(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	log.Debugf("Finding the CRI API runtime version")
	r.runtimeClient = runtimeapi.NewRuntimeServiceClient(conn)

	if _, err := r.runtimeClient.Version(ctx, &runtimeapi.VersionRequest{}); err == nil {
		log.Info("Using CRI v1 runtime API")
		r.v1API = true
	} else if status.Code(err) == codes.Unimplemented {
		log.Info("Falling back to CRI v1alpha2 runtime API (deprecated)")
		r.runtimeClientV1alpha2 = runtimeapiV1alpha2.NewRuntimeServiceClient(conn)
	} else {
		return fmt.Errorf("unable to determine runtime API version: %w", err)
	}

	return nil
}

// ContainerStatus makes CRI call to return the container status for the give
// container.  The verbose flag when enabled fetches verbose status.
func (r *runtimeClient) ContainerStatus(containerID string, verbose bool) (*runtimeapi.ContainerStatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	if r.v1API {
		return r.containerStatusV1(ctx, containerID, verbose)
	}

	return r.containerStatusV1alpha2(ctx, containerID, verbose)
}

func (r *runtimeClient) containerStatusV1(ctx context.Context, containerID string, verbose bool) (*runtimeapi.ContainerStatusResponse, error) {
	resp, err := r.runtimeClient.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     verbose,
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (r *runtimeClient) containerStatusV1alpha2(ctx context.Context, containerID string, verbose bool) (*runtimeapi.ContainerStatusResponse, error) {
	resp, err := r.runtimeClientV1alpha2.ContainerStatus(ctx, &runtimeapiV1alpha2.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     verbose,
	})
	if err != nil {
		return nil, err
	}

	return fromV1alpha2ContainerStatusResponse(resp), nil
}

func fromV1alpha2ContainerStatusResponse(from *runtimeapiV1alpha2.ContainerStatusResponse) *runtimeapi.ContainerStatusResponse {
	return (*runtimeapi.ContainerStatusResponse)(unsafe.Pointer(from))
}
