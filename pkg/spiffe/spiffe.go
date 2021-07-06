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
	"math/rand"
	"strconv"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"

	privilegedv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/privileged/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"google.golang.org/grpc"
)

var watcher *spiffeWatcher

// InitWatcher initializes the spiffe watcher instance.
// Users can call Watch() and Unwatch() to add/remove endpoints from the watched
// set.
func InitWatcher() error {
	ret, err := newWatcher(option.Config.SpirePrivilegedAPISocketPath)
	if err != nil {
		return fmt.Errorf("failed to create spiffe watcher: %w", err)
	}

	go ret.watchAllSVIDs()

	watcher = ret

	return nil
}

// Watch adds the pod to the watched list. updateFunc will be called when there
// is an update for such a pod.
func Watch(pod *slim_corev1.Pod, updateFunc UpdateFunc) error {
	if watcher == nil {
		return fmt.Errorf("spiffe watcher not initialized")
	}
	return watcher.watch(pod, updateFunc)
}

// Unwatch removes a pod from the watched list.
func Unwatch(pod *slim_corev1.Pod) error {
	if watcher == nil {
		return fmt.Errorf("spiffe watcher not initialized")
	}
	return watcher.unwatch(pod)
}

type SpiffeSVID struct {
	SpiffeID  string
	CertChain []byte
	Key       []byte
}

type UpdateFunc func([]*SpiffeSVID)

type spiffeWatcher struct {
	client privilegedv1.PrivilegedClient

	stream privilegedv1.Privileged_WatchX509SVIDsClient

	updateFuncs map[uint64]UpdateFunc
	ids         map[*slim_corev1.Pod]uint64
}

func newWatcher(spireSocketPath string) (*spiffeWatcher, error) {
	client, err := newPrivilegedClient(spireSocketPath)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	stream, err := client.WatchX509SVIDs(ctx)
	if err != nil {
		return nil, err
	}

	ret := &spiffeWatcher{
		client:      client,
		stream:      stream,
		updateFuncs: make(map[uint64]UpdateFunc),
		ids:         make(map[*slim_corev1.Pod]uint64),
	}

	return ret, nil
}

func (s *spiffeWatcher) watch(pod *slim_corev1.Pod, updateFunc UpdateFunc) error {
	id := rand.Uint64()

	req := &privilegedv1.WatchX509SVIDsRequest{
		Operation: privilegedv1.WatchX509SVIDsRequest_ADD,
		Id:        id,
		Selectors: getPodSelectors(pod),
	}

	s.updateFuncs[id] = updateFunc
	s.ids[pod] = id

	err := s.stream.Send(req)
	if err != nil {
		return err
	}

	return nil
}

func (s *spiffeWatcher) unwatch(pod *slim_corev1.Pod) error {
	if pod == nil {
		return nil
	}
	id, ok := s.ids[pod]
	if !ok {
		return fmt.Errorf("spiffe ID for pod %s not found", pod.Name)
	}

	req := &privilegedv1.WatchX509SVIDsRequest{
		Operation: privilegedv1.WatchX509SVIDsRequest_DEL,
		Id:        id,
	}

	err := s.stream.Send(req)
	if err != nil {
		return err
	}

	delete(s.updateFuncs, id)
	delete(s.ids, pod)

	return nil
}

func (s *spiffeWatcher) watchAllSVIDs() {
	for {
		resp, err := s.stream.Recv()
		if err != nil {
			return
		}

		updateFunc, ok := s.updateFuncs[resp.Id]
		if !ok {
			continue
		}

		spiffeSvids := make([]*SpiffeSVID, len(resp.Response.X509Svids))
		for idx, svid := range resp.Response.X509Svids {
			spiffeSvids[idx] = &SpiffeSVID{
				SpiffeID: spiffeIDToString(svid.X509Svid.Id),
			}
		}

		updateFunc(spiffeSvids)
	}
}

func newPrivilegedClient(socketPath string) (privilegedv1.PrivilegedClient, error) {
	unixPath := "unix://" + socketPath

	conn, err := grpc.Dial(unixPath, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to privileged SPIRE api: %w", err)
	}

	return privilegedv1.NewPrivilegedClient(conn), nil
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

func spiffeIDToString(id *types.SPIFFEID) string {
	return "spiffe://" + id.TrustDomain + id.Path
}
