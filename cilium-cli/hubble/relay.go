// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/internal/utils"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (p *Parameters) RelayPortForwardCommand(ctx context.Context, client k8sHubbleImplementation) error {
	relaySvc, err := client.GetService(ctx, p.Namespace, "hubble-relay", metav1.GetOptions{})
	if err != nil {
		return err
	}

	args := []string{
		"port-forward",
		"-n", p.Namespace,
		"svc/hubble-relay",
		"--address", "127.0.0.1",
		fmt.Sprintf("%d:%d", p.PortForward, relaySvc.Spec.Ports[0].Port)}

	if p.Context != "" {
		args = append([]string{"--context", p.Context}, args...)
	}

	_, err = utils.Exec(p, "kubectl", args...)
	return err
}
