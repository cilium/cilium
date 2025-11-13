/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package leaderelection

import (
	"errors"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/uuid"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"sigs.k8s.io/controller-runtime/pkg/recorder"
)

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// Options provides the required configuration to create a new resource lock.
type Options struct {
	// LeaderElection determines whether or not to use leader election when
	// starting the manager.
	LeaderElection bool

	// LeaderElectionResourceLock determines which resource lock to use for leader election,
	// defaults to "leases".
	LeaderElectionResourceLock string

	// LeaderElectionNamespace determines the namespace in which the leader
	// election resource will be created.
	LeaderElectionNamespace string

	// LeaderElectionID determines the name of the resource that leader election
	// will use for holding the leader lock.
	LeaderElectionID string

	// RenewDeadline is the renew deadline for this leader election client.
	// Must be set to ensure the resource lock has an appropriate client timeout.
	// Without that, a single slow response from the API server can result
	// in losing leadership.
	RenewDeadline time.Duration

	// LeaderLabels are an optional set of labels that will be set on the lease object
	// when this replica becomes leader
	LeaderLabels map[string]string
}

// NewResourceLock creates a new resource lock for use in a leader election loop.
func NewResourceLock(config *rest.Config, recorderProvider recorder.Provider, options Options) (resourcelock.Interface, error) {
	if !options.LeaderElection {
		return nil, nil
	}
	// Default resource lock to "leases". The previous default (from v0.7.0 to v0.11.x) was configmapsleases, which was
	// used to migrate from configmaps to leases. Since the default was "configmapsleases" for over a year, spanning
	// five minor releases, any actively maintained operators are very likely to have a released version that uses
	// "configmapsleases". Therefore defaulting to "leases" should be safe.
	if options.LeaderElectionResourceLock == "" {
		options.LeaderElectionResourceLock = resourcelock.LeasesResourceLock
	}

	// LeaderElectionID must be provided to prevent clashes
	if options.LeaderElectionID == "" {
		return nil, errors.New("LeaderElectionID must be configured")
	}

	// Default the namespace (if running in cluster)
	if options.LeaderElectionNamespace == "" {
		var err error
		options.LeaderElectionNamespace, err = getInClusterNamespace()
		if err != nil {
			return nil, fmt.Errorf("unable to find leader election namespace: %w", err)
		}
	}

	// Leader id, needs to be unique
	id, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	id = id + "_" + string(uuid.NewUUID())

	// Construct config for leader election
	config = rest.AddUserAgent(config, "leader-election")

	// Timeout set for a client used to contact to Kubernetes should be lower than
	// RenewDeadline to keep a single hung request from forcing a leader loss.
	// Setting it to max(time.Second, RenewDeadline/2) as a reasonable heuristic.
	if options.RenewDeadline != 0 {
		timeout := options.RenewDeadline / 2
		if timeout < time.Second {
			timeout = time.Second
		}
		config.Timeout = timeout
	}

	// Construct clients for leader election
	corev1Client, err := corev1client.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	coordinationClient, err := coordinationv1client.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return resourcelock.NewWithLabels(options.LeaderElectionResourceLock,
		options.LeaderElectionNamespace,
		options.LeaderElectionID,
		corev1Client,
		coordinationClient,
		resourcelock.ResourceLockConfig{
			Identity:      id,
			EventRecorder: recorderProvider.GetEventRecorderFor(id),
		},
		options.LeaderLabels,
	)
}

func getInClusterNamespace() (string, error) {
	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	if _, err := os.Stat(inClusterNamespacePath); os.IsNotExist(err) {
		return "", fmt.Errorf("not running in-cluster, please specify LeaderElectionNamespace")
	} else if err != nil {
		return "", fmt.Errorf("error checking namespace file: %w", err)
	}

	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(namespace), nil
}
