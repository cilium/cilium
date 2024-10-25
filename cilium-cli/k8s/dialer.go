// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s"
)

// PortForward executes in a goroutine a port forward command.
// To stop the port-forwarding, use the context by cancelling it
func (c *Client) PortForward(ctx context.Context, p k8s.PortForwardParameters) (*k8s.PortForwardResult, error) {
	return k8s.NewPortForwarder(c.Clientset, c.Config).PortForward(ctx, p)
}
