// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"io"
	"net/http"
	"strings"

	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// ForwardedPort holds the remote and local mapped port.
type ForwardedPort struct {
	Local  uint16
	Remote uint16
}

// PortForwardParameters are the needed parameters to call PortForward.
// Ports value follow the kubectl syntax: <local-port>:<remote-port>
// 5000 means 5000:5000 listening on 5000 port locally, forwarding to 5000 in the pod
// 8888:5000 means listening on 8888 port locally, forwarding to 5000 in the pod
// 0:5000 means listening on a random port locally, forwarding to 5000 in the pod
// :5000 means listening on a random port locally, forwarding to 5000 in the pod
type PortForwardParameters struct {
	Namespace  string
	Pod        string
	Ports      []string
	Addresses  []string
	OutWriters OutWriters
}

// OutWriters holds the two io.Writer needed for the port forward
// one for the output and for the errors.
type OutWriters struct {
	Out    io.Writer
	ErrOut io.Writer
}

// PortForwardResult are the ports that have been forwarded.
type PortForwardResult struct {
	ForwardedPorts []ForwardedPort
}

// PortForward executes in a goroutine a port forward command.
// To stop the port-forwarding, use the context by cancelling it
func (c *Client) PortForward(ctx context.Context, p PortForwardParameters) (*PortForwardResult, error) {
	req := c.Clientset.CoreV1().RESTClient().Post().Namespace(p.Namespace).
		Resource("pods").Name(p.Pod).SubResource(strings.ToLower("PortForward"))

	roundTripper, upgrader, err := spdy.RoundTripperFor(c.Config)
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
