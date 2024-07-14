// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/cilium/cilium-cli/internal/utils"

	"github.com/pkg/browser"
)

func (p *Parameters) UIPortForwardCommand() error {
	args := []string{
		"port-forward",
		"-n", p.Namespace,
		"svc/hubble-ui",
		"--address", "127.0.0.1",
		fmt.Sprintf("%d:80", p.UIPortForward)}

	if p.Context != "" {
		args = append([]string{"--context", p.Context}, args...)
	}

	go func() {
		time.Sleep(5 * time.Second)
		url := fmt.Sprintf("http://localhost:%d", p.UIPortForward)

		if p.UIOpenBrowser {
			// avoid cluttering stdout/stderr when opening the browser
			browser.Stdout = io.Discard
			browser.Stderr = io.Discard
			p.Log("ℹ️  Opening %q in your browser...", url)
			browser.OpenURL(url)
		} else {
			p.Log("ℹ️  Hubble UI is available at %q", url)
		}
	}()

	_, err := utils.Exec(p, "kubectl", args...)
	return err
}
