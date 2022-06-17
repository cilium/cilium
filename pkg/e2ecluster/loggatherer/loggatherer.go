// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loggatherer

import (
	"context"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/cilium/cilium/pkg/e2ecluster/e2ehelpers"
)

const (
	namespace             = "kube-system" // FIXME check
	serviceAccountName    = "cilium-log-gatherer"
	daemonSetName         = "log-gatherer"
	k8sAppName            = "cilium-test-logs"
	image                 = "docker.io/cilium/log-gatherer:v1.1"
	containerName         = "log-gatherer"
	bpfMountPath          = "/sys/fs/bpf"
	bpfMapsMountPathName  = "bpf-maps"
	journaldMountPath     = "/var/log/journald"
	journaldMountPathName = "journald"
	setupWaitTimeout      = 1 * time.Minute
)

type contextKey string

var objectsContextKey = contextKey("objects")

// CreateResources creates a log gatherer ServiceAccount and DaemonSet.
func CreateResources() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return nil, err
		}
		r := client.Resources(namespace)

		// Create the ServiceAccount and DaemonSet.
		objects := []k8s.Object{
			newServiceAccount(),
			newDaemonSet(),
		}
		for _, object := range objects {
			if err := r.Create(ctx, object); err != nil {
				return nil, err
			}
		}

		return context.WithValue(ctx, objectsContextKey, objects), nil
	}
}

// WaitForPodsRunning waits until all the log gatherer pods are running.
func WaitForPodsRunning() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return nil, err
		}
		r := client.Resources(namespace)

		// Get the number of nodes.
		nodeList := &v1.NodeList{}
		if err := r.List(ctx, nodeList); err != nil {
			return nil, err
		}

		// Wait for the log-gatherer pods to exist.
		podList := &v1.PodList{}
		podCondition := conditions.New(r).ResourceListN(podList, len(nodeList.Items), resources.WithLabelSelector(
			labels.FormatLabels(map[string]string{
				"k8s-app": k8sAppName,
			}),
		))
		if err := wait.For(podCondition, wait.WithTimeout(setupWaitTimeout)); err != nil {
			return nil, err
		}

		// Wait for each pod to be running.
		for _, pod := range podList.Items {
			podRunningCondition := conditions.New(r).PodRunning(&pod)
			if err := wait.For(podRunningCondition, wait.WithTimeout(setupWaitTimeout)); err != nil {
				return nil, err
			}
		}

		return ctx, nil
	}
}

// DeleteResources deletes all resources created by Setup.
func DeleteResources() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return nil, err
		}
		r := client.Resources(namespace)

		objects := ctx.Value(objectsContextKey).([]k8s.Object)
		for _, object := range objects {
			if err := r.Delete(ctx, object); err != nil {
				return nil, err
			}

		}

		return ctx, nil
	}
}

// Setup sets up the log gatherer.
func Setup() env.Func {
	return e2ehelpers.Sequence(
		CreateResources(),
		WaitForPodsRunning(),
	)
}

// Finish cleans up the log gatherer.
func Finish() env.Func {
	return DeleteResources()
}

func newServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
		},
	}
}

func newDaemonSet() *appsv1.DaemonSet {
	hostPathDirectoryOrCreate := v1.HostPathDirectoryOrCreate
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      daemonSetName,
			Namespace: namespace,
			Labels: map[string]string{
				"k8s-app": k8sAppName,
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app":                       k8sAppName,
					"kubernetes.io/cluster-service": "true",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app":                       k8sAppName,
						"kubernetes.io/cluster-service": "true",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Args: []string{
								"10000",
							},
							Command: []string{
								"sleep",
							},
							Image:           image,
							ImagePullPolicy: v1.PullIfNotPresent,
							Name:            containerName,
							SecurityContext: &v1.SecurityContext{
								Privileged: pointer.Bool(true),
							},
							VolumeMounts: []v1.VolumeMount{
								{
									MountPath: bpfMountPath,
									Name:      bpfMapsMountPathName,
								},
								{
									MountPath: journaldMountPath,
									Name:      journaldMountPathName,
								},
							},
						},
					},
					DNSPolicy:                     v1.DNSClusterFirstWithHostNet,
					HostNetwork:                   true,
					HostPID:                       true,
					PriorityClassName:             "system-node-critical",
					RestartPolicy:                 v1.RestartPolicyAlways,
					ServiceAccountName:            serviceAccountName,
					TerminationGracePeriodSeconds: pointer.Int64(1),
					Tolerations: []v1.Toleration{
						{
							Operator: v1.TolerationOpExists,
						},
					},
					Volumes: []v1.Volume{
						{
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: bpfMountPath,
									Type: &hostPathDirectoryOrCreate,
								},
							},
							Name: bpfMapsMountPathName,
						},
						{
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: journaldMountPath,
									Type: &hostPathDirectoryOrCreate,
								},
							},
							Name: journaldMountPathName,
						},
					},
				},
			},
		},
	}
}
