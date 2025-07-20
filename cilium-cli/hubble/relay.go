// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/k8s"
)

func (p *Parameters) RelayPortForwardCommand(ctx context.Context, k8sClient *k8s.Client) error {
	// default to first port configured on the service when svcPort is set to 0
	res, err := k8sClient.PortForwardService(ctx, p.Namespace, "hubble-relay", int32(p.PortForward), 0)
	if err != nil {
		return fmt.Errorf("failed to port forward: %w", err)
	}
	p.Log("ℹ️  Hubble Relay is available at 127.0.0.1:%d", res.ForwardedPort.Local)
	<-ctx.Done()
	return nil
}
