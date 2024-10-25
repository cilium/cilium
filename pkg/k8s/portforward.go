// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"io"
	"net/http"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// ForwardedPort holds the local and remote mapped ports.
type ForwardedPort struct {
	Local  uint16
	Remote uint16
}

// PortForwardParameters are the needed parameters to call PortForward.
//
// Ports value follow the kubectl syntax: <local-port>:<remote-port>:
//   - 5000 means 5000:5000 listening on 5000 port locally, forwarding to 5000 in the pod
//   - 8888:5000 means listening on 8888 port locally, forwarding to 5000 in the pod
//   - 0:5000 means listening on a random port locally, forwarding to 5000 in the pod
//   - :5000 means listening on a random port locally, forwarding to 5000 in the pod
type PortForwardParameters struct {
	Namespace  string
	Pod        string
	Ports      []string
	Addresses  []string
	OutWriters OutWriters
}

// OutWriters holds the two io.Writer used by the port forward.
// These can be safely disabled by setting them to nil.
type OutWriters struct {
	Out    io.Writer
	ErrOut io.Writer
}

// PortForwarder augments the k8s client-go PortForwarder with helper methods using a clientset.
type PortForwarder struct {
	clientset kubernetes.Interface
	config    *rest.Config
}

// NewPortForwarder creates a new PortForwarder ready to use.
func NewPortForwarder(clientset kubernetes.Interface, config *rest.Config) *PortForwarder {
	return &PortForwarder{clientset: clientset, config: config}
}

// PortForwardResult are the ports that have been forwarded by PortForward.
type PortForwardResult struct {
	ForwardedPorts []ForwardedPort
}

// PortForward executes in a goroutine a port forward command.
// To stop the port-forwarding, use the context by cancelling it.
func (pf *PortForwarder) PortForward(ctx context.Context, p PortForwardParameters) (*PortForwardResult, error) {
	req := pf.clientset.CoreV1().RESTClient().Post().Namespace(p.Namespace).
		Resource("pods").Name(p.Pod).SubResource(strings.ToLower("PortForward"))

	roundTripper, upgrader, err := spdy.RoundTripperFor(pf.config)
	if err != nil {
		return nil, err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, req.URL())
	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{}, 1)
	if len(p.Addresses) == 0 {
		p.Addresses = []string{"localhost"}
	}

	pw, err := portforward.NewOnAddresses(dialer, p.Addresses, p.Ports, stopChan, readyChan, p.OutWriters.Out, p.OutWriters.ErrOut)
	if err != nil {
		return nil, err
	}

	errChan := make(chan error, 1)
	go func() {
		if err := pw.ForwardPorts(); err != nil {
			errChan <- err
		}
	}()

	go func() {
		<-ctx.Done()
		close(stopChan)
	}()

	select {
	case <-pw.Ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errChan:
		return nil, err
	}

	ports, err := pw.GetPorts()
	if err != nil {
		return nil, err
	}

	forwardedPorts := make([]ForwardedPort, 0, len(ports))
	for _, port := range ports {
		forwardedPorts = append(forwardedPorts, ForwardedPort{port.Local, port.Remote})
	}

	return &PortForwardResult{
		ForwardedPorts: forwardedPorts,
	}, nil
}
