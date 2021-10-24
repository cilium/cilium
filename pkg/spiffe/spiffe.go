// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spiffe

import (
	"context"
	"fmt"
	"strconv"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"google.golang.org/grpc"
)

// InitWatcher connects to spire control plane
// Cilium can subscribe to spire based on pod selectors and start receiving
// SVID updates.
func InitWatcher(pod *slim_corev1.Pod) (delegatedidentityv1.DelegatedIdentity_SubscribeToX509SVIDsClient, error) {
	sockPath := option.Config.SpirePrivilegedAPISocketPath
	unixPath := "unix://" + sockPath

	conn, err := grpc.Dial(unixPath, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("Spiffe: Cilium grpc.Dial() failed on %s: %s", sockPath, err)
	}

	client := delegatedidentityv1.NewDelegatedIdentityClient(conn)

	req := &delegatedidentityv1.SubscribeToX509SVIDsRequest{
		Selectors: getPodSelectors(pod),
	}

	stream, err := client.SubscribeToX509SVIDs(context.Background(), req)

	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("Spiffe: Cilium stream failed on %s: %s", sockPath, err)
	}

	return stream, nil
}

func makeSelector(format string, args ...interface{}) *types.Selector {
	return &types.Selector{
		Type:  "k8s",
		Value: fmt.Sprintf(format, args...),
	}
}

func getPodSelectors(pod *slim_corev1.Pod) []*types.Selector {
	// missing ones:
	// - image with sha256
	// - owner references
	selectors := []*types.Selector{
		makeSelector("sa:%s", pod.Spec.ServiceAccountName),
		makeSelector("ns:%s", pod.Namespace),
		makeSelector("node-name:%s", pod.Spec.NodeName),
		makeSelector("pod-uid:%s", pod.UID),
		makeSelector("pod-name:%s", pod.Name),
		makeSelector("pod-image-count:%s", strconv.Itoa(len(pod.Spec.Containers))),
		makeSelector("pod-init-image-count:%s", strconv.Itoa(len(pod.Spec.InitContainers))),
	}

	for _, container := range pod.Spec.Containers {
		selectors = append(selectors, makeSelector("pod-image:%s", container.Image))
	}
	for _, container := range pod.Spec.InitContainers {
		selectors = append(selectors, makeSelector("pod-init-image:%s", container.Image))
	}

	for k, v := range pod.Labels {
		selectors = append(selectors, makeSelector("pod-label:%s:%s", k, v))
	}
	//	for _, ownerReference := range pod.OwnerReferences {
	//		selectors = append(selectors, makeSelector("pod-owner:%s:%s", ownerReference.Kind, ownerReference.Name))
	//		selectors = append(selectors, makeSelector("pod-owner-uid:%s:%s", ownerReference.Kind, ownerReference.UID))
	//	}

	return selectors
}

func SpiffeIDToString(id *types.SPIFFEID) string {
	return id.TrustDomain + id.Path
}
