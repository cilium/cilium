// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"context"
	"fmt"
	"io"

	"github.com/pkg/browser"

	"github.com/cilium/cilium/cilium-cli/k8s"
)

func (p *Parameters) UIPortForwardCommand(ctx context.Context, k8sClient *k8s.Client) error {
	// default to first port configured on the service when svcPort is set to 0
	res, err := k8sClient.PortForwardService(ctx, p.Namespace, "hubble-ui", int32(p.UIPortForward), 0)
	if err != nil {
		return fmt.Errorf("failed to port forward: %w", err)
	}

	url := fmt.Sprintf("http://localhost:%d", res.ForwardedPort.Local)
	if p.UIOpenBrowser {
		// avoid cluttering stdout/stderr when opening the browser
		browser.Stdout = io.Discard
		browser.Stderr = io.Discard
		p.Log("ℹ️  Opening %q in your browser...", url)
		browser.OpenURL(url)
	} else {
		p.Log("ℹ️  Hubble UI is available at %q", url)
	}

	<-ctx.Done()
	return nil
}
