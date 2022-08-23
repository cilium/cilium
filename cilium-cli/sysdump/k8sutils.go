// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// ensureExecTarget ensures, if at all possible, that a target for execution exists. If the
// selected container is up and running, it uses that. If the container is not (because it has crashed),
// then either an EphemeralContainer or new Pod will be created.
// In all cases, a cleanup function will be returned to remove any resources that may be created.
// This assumes the target image has /bin/sleep
func (c *Collector) ensureExecTarget(ctx context.Context, pod *corev1.Pod, container string) (targetPod *corev1.Pod, targetContainer string, cleanup func(context.Context) error, err error) {
	cleanup = func(_ context.Context) error { return nil }

	// case 1: target container is running
	found := false
	for _, c := range pod.Status.ContainerStatuses {
		if c.Name == container {
			if c.State.Running != nil {
				return pod, container, cleanup, nil
			}
			found = true
			break
		}
	}
	if !found {
		return nil, "", cleanup, fmt.Errorf("could not find container %q in pod %q with namespace %q", container, pod.Name, pod.Namespace)
	}

	// case 2: try to create an EphemeralContainer
	// This is beta as of k8s 1.23, and may be blocked behind a FeatureGate,
	// so continue to case 3 if this fails.
	var fromContainer *corev1.Container
	for _, cs := range pod.Spec.Containers {
		if cs.Name == container {
			fromContainer = cs.DeepCopy()
			break
		}
	}
	if fromContainer == nil {
		// impossible, we checked above
		return nil, "", cleanup, fmt.Errorf("could not find container %s", container)
	}

	c.logWarn("Container %q for pod %q in namespace %q is not running. Trying EphemeralContainer or separate Pod instead...", container, pod.Name, pod.Namespace)
	ec := &corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:            fmt.Sprintf("sysdump-%d", time.Now().Unix()),
			Image:           fromContainer.Image,
			Command:         []string{"/bin/sleep", "1d"},
			Env:             fromContainer.Env,
			VolumeMounts:    fromContainer.VolumeMounts,
			SecurityContext: fromContainer.SecurityContext,
		},
		TargetContainerName: fromContainer.Name,
	}

	targetPod, err = c.Client.CreateEphemeralContainer(ctx, pod, ec)
	if err == nil {
		c.logDebug("Created EphemeralContainer %q on pod %q in namespace %q", ec.Name, pod.Name, pod.Namespace)

		// Ephemeral container created, wait for it to enter Running status.
		err = wait.PollWithContext(ctx, 10*time.Second, 30*time.Second, func(ctx context.Context) (bool, error) {
			var err error
			targetPod, err = c.Client.GetPod(ctx, targetPod.Namespace, targetPod.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			for _, status := range targetPod.Status.EphemeralContainerStatuses {
				if status.Name == ec.Name {
					return status.State.Running != nil, nil
				}
			}
			return false, nil
		})
		if err == nil {
			return targetPod, ec.Name, cleanup, nil
		}
		c.logWarn("EphemeralContainer %q on pod %q in namespace %q never reached Running status (falling back to separate Pod)", ec.Name, targetPod.Name, targetPod.Namespace)
	} else {
		c.logDebug("Could not create EphemeralContainer (falling back to separate Pod): %v", err)
	}

	// case 3: create another Pod on the same node, with as much of the configuration copied over as possible.
	c.logWarn("Container %q on pod %q in namespace %q is not running. Creating exec Pod.", container, pod.Name, pod.Namespace)

	// Create a copy pod with most of the interesting fields copied over.
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    pod.Namespace,
			GenerateName: "sysdump-",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            fromContainer.Name,
					Image:           fromContainer.Image,
					Command:         []string{"/bin/sleep", "1d"},
					Env:             fromContainer.Env,
					VolumeMounts:    fromContainer.VolumeMounts,
					SecurityContext: fromContainer.SecurityContext,
				},
			},
			Volumes:            pod.Spec.Volumes,
			RestartPolicy:      corev1.RestartPolicyNever,
			DNSPolicy:          pod.Spec.DNSPolicy,
			ServiceAccountName: pod.Spec.ServiceAccountName,
			NodeName:           pod.Spec.NodeName,
			HostNetwork:        pod.Spec.HostNetwork,
			HostPID:            pod.Spec.HostPID,
			HostIPC:            pod.Spec.HostIPC,
			SecurityContext:    pod.Spec.SecurityContext,
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists, // Tolerate everything.
				},
			},
		},
	}
	targetContainer = fromContainer.Name

	targetPod, err = c.Client.CreatePod(ctx, pod.Namespace, newPod, metav1.CreateOptions{})
	if err != nil {
		err = fmt.Errorf("could not create exec pod: %w", err)
		return
	}
	c.logDebug("Created exec pod %q/%q on node %q", targetPod.Namespace, targetPod.Name, targetPod.Spec.NodeName)

	cleanup = func(ctx context.Context) error {
		c.logDebug("Deleting exec pod %s/%s", targetPod.Namespace, targetPod.Name)
		return c.Client.DeletePod(ctx, targetPod.Namespace, targetPod.Name, metav1.DeleteOptions{})
	}

	// Wait up to 2 minutes for pod to be available
	err = wait.PollWithContext(ctx, 10*time.Second, 2*time.Minute, func(ctx context.Context) (bool, error) {
		var err error
		targetPod, err = c.Client.GetPod(ctx, targetPod.Namespace, targetPod.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, condition := range targetPod.Status.Conditions {
			if condition.Type == corev1.ContainersReady && condition.Status == "True" {
				return true, nil
			}
		}
		return false, nil
	})

	if err != nil {
		_ = cleanup(ctx) // best-effort delete
		return nil, "", func(_ context.Context) error { return nil }, fmt.Errorf("exec pod %q for namespace %q never reached ready status: %w", targetPod.Name, targetPod.Namespace, err)
	}

	return targetPod, targetContainer, cleanup, nil
}
