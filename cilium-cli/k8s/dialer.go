// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s/portforward"
)

// PortForward executes in a goroutine a port forward command.
// To stop the port-forwarding, use the context by cancelling it
func (c *Client) PortForward(ctx context.Context, p portforward.PortForwardParameters) (*portforward.PortForwardResult, error) {
	return portforward.NewPortForwarder(c.Clientset, c.Config).PortForward(ctx, p)
}

// PortForwardService executes in a goroutine a port forward command towards one of the pod behind a
// service. If `localPort` is 0, a random port is selected. If `svcPort` is 0, uses the first port
// configured on the service.
//
// To stop the port-forwarding, use the context by cancelling it.
func (c *Client) PortForwardService(ctx context.Context, namespace, name string, localPort, svcPort int32) (*portforward.PortForwardServiceResult, error) {
	return portforward.NewPortForwarder(c.Clientset, c.Config).PortForwardService(ctx, namespace, name, localPort, svcPort)
}
