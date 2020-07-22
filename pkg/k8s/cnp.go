// Copyright 2016-2020 Authors of Cilium
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

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/backoff"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

// ErrParse is an error to describe where policy fails to parse due any invalid
// rule.
type ErrParse struct {
	msg string
}

// Error returns the error message for parsing
func (e ErrParse) Error() string {
	return e.msg
}

// IsErrParse returns true if the error is a ErrParse
func IsErrParse(e error) bool {
	_, ok := e.(ErrParse)
	return ok
}

// CNPStatusUpdateContext is the context required to update the status of a
// CNP. It is filled out by the owner of the Kubernetes client before
// UpdateStatus() is called.
type CNPStatusUpdateContext struct {
	// CiliumNPClient is the CiliumNetworkPolicy client
	CiliumNPClient clientset.Interface

	// CiliumV2Store is a store containing all CiliumNetworkPolicy
	CiliumV2Store cache.Store

	// NodeName is the name of the node, it is used to separate status
	// field entries per node
	NodeName string

	// NodeManager implements the backoff.NodeManager interface and is used
	// to provide cluster-size dependent backoff
	NodeManager backoff.NodeManager

	// UpdateDuration must be populated using spanstart.Start() to provide
	// the timestamp of when the status update operation was started. It is
	// used to provide the latency in the Prometheus metrics.
	UpdateDuration *spanstat.SpanStat

	// WaitForEndpointsAtPolicyRev must point to a function that will wait
	// for all local endpoints to reach the particular policy revision
	WaitForEndpointsAtPolicyRev func(ctx context.Context, rev uint64) error
}

// getUpdatedCNPFromStore gets the most recent version of cnp from the store
// ciliumV2Store, which is updated by the Kubernetes watcher. This reduces
// the possibility of Cilium trying to update cnp in Kubernetes which has
// been updated between the time the watcher in this Cilium instance has
// received cnp, and when this function is called. This still may occur, though
// and users of the returned CiliumNetworkPolicy may not be able to update
// the cnp because it may become out-of-date. Returns an error if the CNP cannot
// be retrieved from the store, or the object retrieved from the store is not of
// the expected type.
func (c *CNPStatusUpdateContext) getUpdatedCNPFromStore(cnp *types.SlimCNP) (*types.SlimCNP, error) {
	serverRuleStore, exists, err := c.CiliumV2Store.Get(cnp)
	if err != nil {
		return nil, fmt.Errorf("unable to find v2.CiliumNetworkPolicy in local cache: %s", err)
	}
	if !exists {
		return nil, errors.New("v2.CiliumNetworkPolicy does not exist in local cache")
	}

	serverRule, ok := serverRuleStore.(*types.SlimCNP)
	if !ok {
		return nil, errors.New("received object of unknown type from API server, expecting v2.CiliumNetworkPolicy")
	}

	return serverRule, nil
}

func (c *CNPStatusUpdateContext) prepareUpdate(cnp *types.SlimCNP, scopedLog *logrus.Entry) (serverRule *types.SlimCNP, err error) {
	var localCopy *types.SlimCNP

	if c.CiliumV2Store != nil {
		localCopy, err = c.getUpdatedCNPFromStore(cnp)
		if err != nil {
			scopedLog.WithError(err).Debug("error getting updated CNP from store")
			return
		}

		// Make a copy since the rule is a pointer, and any of its fields
		// which are also pointers could be modified outside of this
		// function.
		serverRule = localCopy.DeepCopy()
		_, err = serverRule.Parse()
		if err != nil {
			err = ErrParse{err.Error()}
			scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(serverRule)).
				Warn("Error parsing new CiliumNetworkPolicy rule")
		} else {
			scopedLog.WithField("cnpFromStore", serverRule.String()).Debug("copy of CNP retrieved from store which is being updated with status")
		}

		return
	}

	serverRule = cnp
	_, err = cnp.Parse()
	if err != nil {
		log.WithError(err).WithField(logfields.Object, logfields.Repr(serverRule)).
			Warn("Error parsing new CiliumNetworkPolicy rule")
		err = ErrParse{err.Error()}
	}

	return
}

func (c *CNPStatusUpdateContext) updateStatus(ctx context.Context, cnp *types.SlimCNP, rev uint64, policyImportErr, waitForEPsErr error) (err error) {
	// Update the status of whether the rule is enforced on this node.  If
	// we are unable to parse the CNP retrieved from the store, or if
	// endpoints did not reach the desired policy revision after 30
	// seconds, then mark the rule as not being enforced.
	if policyImportErr != nil {
		// OK is false here because the policy wasn't imported into
		// cilium on this node; since it wasn't imported, it also isn't
		// enforced.
		if option.Config.K8sEventHandover {
			err = c.updateViaKVStore(ctx, cnp, false, false, policyImportErr, rev, cnp.Annotations)
		} else {
			err = c.updateViaAPIServer(cnp, false, false, policyImportErr, rev, cnp.Annotations)
		}
	} else {
		// If the deadline by the above context, then not all endpoints
		// are enforcing the given policy, and waitForEpsErr will be
		// non-nil.
		if option.Config.K8sEventHandover {
			err = c.updateViaKVStore(ctx, cnp, waitForEPsErr == nil, true, waitForEPsErr, rev, cnp.Annotations)
		} else {
			err = c.updateViaAPIServer(cnp, waitForEPsErr == nil, true, waitForEPsErr, rev, cnp.Annotations)
		}
	}

	return
}

// UpdateStatus updates the status section of a CiliumNetworkPolicy. It will
// retry as long as required to update the status unless a non-temporary error
// occurs in which case it expects a surrounding controller to restart or give
// up.
func (c *CNPStatusUpdateContext) UpdateStatus(ctx context.Context, cnp *types.SlimCNP, rev uint64, policyImportErr error) error {
	var (
		err        error
		serverRule *types.SlimCNP

		// The following is an example distribution with jitter applied:
		//
		// nodes      4        16       128       512      1024      2048
		// 1:      2.6s      5.5s      8.1s        9s      9.9s     12.9s
		// 2:      1.9s      4.2s      6.3s     11.9s     17.6s     26.2s
		// 3:        4s     10.4s     15.7s     26.7s     20.7s     23.3s
		// 4:       18s     12.1s     19.7s       40s    1m6.3s   1m46.3s
		// 5:     16.2s     28.9s   1m58.2s     46.2s      2m0s      2m0s
		// 6:     54.7s      7.9s     53.3s      2m0s      2m0s     45.8s
		// 7:   1m55.5s     22.8s      2m0s      2m0s      2m0s      2m0s
		// 8:   1m45.8s   1m36.7s      2m0s      2m0s      2m0s      2m0s
		cnpBackoff = backoff.Exponential{
			Min:         time.Second,
			NodeManager: c.NodeManager,
			Jitter:      true,
		}

		scopedLog = log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
		})
	)
	ctxEndpointWait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	waitForEPsErr := c.WaitForEndpointsAtPolicyRev(ctxEndpointWait, rev)

	numAttempts := 0
retryLoop:
	for {
		numAttempts++

		select {
		case <-ctx.Done():
			// The owning controller wants us to stop, no error is
			// returned. This is graceful
			err = fmt.Errorf("status update cancelled via context: %s", ctx.Err())
			break retryLoop
		default:
		}

		// Failure to prepare are returned as error immediately to
		// expose them via the controller status as these errors are
		// most likely not temporary.
		// In case of a CNP parse error will update the status in the CNP.
		serverRule, err = c.prepareUpdate(cnp, scopedLog)
		if IsErrParse(err) {
			statusErr := c.updateStatus(ctx, serverRule, rev, err, waitForEPsErr)
			if statusErr != nil {
				scopedLog.WithError(statusErr).Debug("CNP status for invalid rule cannot be updated")
			}
		}
		if err != nil {
			return err
		}

		err = c.updateStatus(ctx, serverRule, rev, policyImportErr, waitForEPsErr)
		scopedLog.WithError(err).WithField("status", serverRule.Status).Debug("CNP status update result from apiserver")

		switch {
		case waitForEPsErr != nil:
			// Waiting for endpoints has failed previously. We made
			// an attempt to make this error condition visible via
			// the status field. Regardless of whether this has
			// succeeded or not, return an error to have the
			// surrounding controller retry the wait for endpoint
			// state.
			err = waitForEPsErr
			break retryLoop

		case err == nil:
			// The status update was successful
			break retryLoop
		}

		cnpBackoff.Wait(ctx)
		// error of Wait() can be ignored, if the context is cancelled,
		// the next iteration of the loop will break out
	}

	outcome := metrics.LabelValueOutcomeSuccess
	if err != nil {
		outcome = metrics.LabelValueOutcomeFail
	}

	if c.UpdateDuration != nil {
		latency := c.UpdateDuration.End(err == nil).Total()
		metrics.KubernetesCNPStatusCompletion.WithLabelValues(fmt.Sprintf("%d", numAttempts), outcome).Observe(latency.Seconds())
	}

	return err
}

// CNPStatusesPath is the prefix in the kvstore which will contain all keys
// representing CNPStatus state for all nodes in the cluster.
var CNPStatusesPath = path.Join(kvstore.BaseKeyPrefix, "state", "cnpstatuses", "v2")

// formatKeyNodeForKvstore formats the key to be used for kvstore, it takes into
// consideration the namespaced nature of the resource, so if the namespace
// provided is empty then it assumes that the resource corresponding to the key
// is a clusterwide resource.
func formatKeyNodeForKvstore(o K8sMetaObject, nodeName string) string {
	return path.Join(formatKeyForKvstore(o), nodeName)
}

func formatKeyForKvstore(o K8sMetaObject) string {
	if o.GetNamespace() != "" {
		return path.Join(CNPStatusesPath, getKeyFromObject(o))
	}

	return path.Join(CCNPStatusesPath, getKeyFromObject(o))
}

func (c *CNPStatusUpdateContext) updateViaAPIServer(cnp *types.SlimCNP, enforcing, ok bool, cnpError error, rev uint64, cnpAnnotations map[string]string) error {
	var (
		cnpns       cilium_v2.CiliumNetworkPolicyNodeStatus
		annotations map[string]string
	)
	capabilities := k8sversion.Capabilities()

	switch {
	case cnpAnnotations == nil:
		// don't bother doing anything if cnpAnnotations is nil.
	case capabilities.Patch:
		// in k8s versions that support JSON Patch we can safely modify the
		// cnpAnnotations as the CNP, along with these annotations, is not sent to
		// k8s api-server.
		annotations = cnpAnnotations
		lastAppliedConfig, ok := annotations[v1.LastAppliedConfigAnnotation]
		if ok {
			defer func() {
				cnpAnnotations[v1.LastAppliedConfigAnnotation] = lastAppliedConfig
			}()
		}
	default:
		// for all other k8s versions, sense the CNP is sent with the
		// annotations we need to make a deepcopy.
		m := make(map[string]string, len(cnpAnnotations))
		for k, v := range cnpAnnotations {
			m[k] = v
		}
		annotations = m
	}

	// Ignore LastAppliedConfigAnnotation as it can be really costly to upload
	// this as part of the status.
	delete(annotations, v1.LastAppliedConfigAnnotation)

	cnpns = cilium_v2.CreateCNPNodeStatus(enforcing, ok, cnpError, rev, annotations)

	ns := k8sUtils.ExtractNamespace(&cnp.ObjectMeta)
	return updateStatusesByCapabilities(c.CiliumNPClient, capabilities, cnp, ns, cnp.GetName(), map[string]cilium_v2.CiliumNetworkPolicyNodeStatus{c.NodeName: cnpns})

}

func (c *CNPStatusUpdateContext) updateViaKVStore(ctx context.Context, cnp *types.SlimCNP, enforcing, ok bool, cnpError error, rev uint64, cnpAnnotations map[string]string) error {
	var (
		cnpns       cilium_v2.CiliumNetworkPolicyNodeStatus
		annotations map[string]string
	)

	if err := <-kvstore.Client().Connected(ctx); err != nil {
		return fmt.Errorf("kvstore is unavailable: %w", err)
	}

	capabilities := k8sversion.Capabilities()

	switch {
	case cnpAnnotations == nil:
		// don't bother doing anything if cnpAnnotations is nil.
	case capabilities.Patch:
		// in k8s versions that support JSON Patch we can safely modify the
		// cnpAnnotations as the CNP, along with these annotations, is not sent to
		// k8s api-server.
		annotations = cnpAnnotations
		lastAppliedConfig, ok := annotations[v1.LastAppliedConfigAnnotation]
		defer func() {
			if ok {
				cnpAnnotations[v1.LastAppliedConfigAnnotation] = lastAppliedConfig
			}
		}()
	default:
		// for all other k8s versions, sense the CNP is sent with the
		// annotations we need to make a deepcopy.
		m := make(map[string]string, len(cnpAnnotations))
		for k, v := range cnpAnnotations {
			m[k] = v
		}
		annotations = m
	}

	// Ignore LastAppliedConfigAnnotation as it can be really costly to upload
	// this as part of the status.
	delete(annotations, v1.LastAppliedConfigAnnotation)

	cnpns = cilium_v2.CreateCNPNodeStatus(enforcing, ok, cnpError, rev, annotations)

	cnpWithMeta := CNPNSWithMeta{
		Name:                          cnp.GetName(),
		Namespace:                     cnp.GetNamespace(),
		UID:                           cnp.GetUID(),
		CiliumNetworkPolicyNodeStatus: cnpns,
		Node:                          nodeTypes.GetName(),
	}
	marshaledVal, err := json.Marshal(cnpWithMeta)
	if err != nil {
		return err
	}

	// If the namespace is empty it means that the policy is clusterwide policy.
	// This is then taken care of internally when we try to join the path using
	// golangs `path.Join`
	key := formatKeyNodeForKvstore(cnp.GetObjectMeta(), nodeTypes.GetName())
	log.WithFields(logrus.Fields{
		"key":   key,
		"value": marshaledVal,
	}).Debug("updating CNPStatus in kvstore")
	return kvstore.Client().Update(ctx, key, marshaledVal, true)
}

// CNPNSWithMeta is a wrapper around a CiliumNetworkPolicyNodeStatus with
// metadata that uniquely identifies the CNP which is being updated, and the
// node to which the status update corresponds.
// Implements pkg/kvstore/store/Key.
type CNPNSWithMeta struct {
	UID       k8sTypes.UID
	Namespace string
	Name      string
	Node      string
	cilium_v2.CiliumNetworkPolicyNodeStatus
}

// GetKeyName returns the uniquely identifying information of this CNPNSWithMeta
// as a string for use as a key in a map.
func (c *CNPNSWithMeta) GetKeyName() string {
	return path.Join(getKeyFromObject(c), c.Node)
}

// Marshal marshals the CNPNSWithMeta into JSON form.
func (c *CNPNSWithMeta) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

// Unmarshal unmarshals the CNPNSWithMeta from JSON form.
func (c *CNPNSWithMeta) Unmarshal(data []byte) error {
	newCNPNS := CNPNSWithMeta{}
	if err := json.Unmarshal(data, &newCNPNS); err != nil {
		return err
	}

	*c = newCNPNS

	return nil
}

func (c CNPNSWithMeta) GetUID() k8sTypes.UID {
	return c.UID
}

func (c CNPNSWithMeta) GetNamespace() string {
	return c.Namespace
}

func (c CNPNSWithMeta) GetName() string {
	return c.Name
}

// updateStatusesByCapabilities updates the status for all of the nodes in
// nodeStatuses for the CNP. Note that the nodeStatuses map will be updated in
// this function. After this function returns, if non-empty, it will contain the
// set of node status updates which failed / did not occur.
func updateStatusesByCapabilities(client clientset.Interface, capabilities k8sversion.ServerCapabilities, cnp *types.SlimCNP, ns, name string, nodeStatuses map[string]cilium_v2.CiliumNetworkPolicyNodeStatus) error {
	var err error
	switch {
	case capabilities.Patch:
		// This is a JSON Patch [RFC 6902] used to create the `/status/nodes`
		// field in the CNP. If we don't create, replacing the status for this
		// node will fail as the path does not exist.
		// Worst case scenario is that all nodes try to perform this operation
		// and only one node will succeed. This can be moved to the
		// cilium-operator which will create the path for all nodes. However
		// performance tests have shown that performing 2 API calls to
		// kube-apiserver for 500 nodes versus performing 1 API call, where
		// one of the nodes would "create" the `/status` path before all other
		// nodes tried to replace their own status resulted in a gain of 3 %.
		// This gain is less notable once the number of nodes increases.
		createStatusAndNodePatch := []JSONPatch{
			{
				OP:    "test",
				Path:  "/status",
				Value: nil,
			},
			{
				OP:   "add",
				Path: "/status",
				Value: cilium_v2.CiliumNetworkPolicyStatus{
					Nodes: nodeStatuses,
				},
			},
		}

		var createStatusAndNodePatchJSON []byte
		createStatusAndNodePatchJSON, err = json.Marshal(createStatusAndNodePatch)
		if err != nil {
			return err
		}

		// If the patch fails it means the "test" from the previous patch
		// failed so we can safely replace the nodes in the CNP status.
		// If namespace is empty we understand that the policy corresponds to the clusterwide policy
		// in that case we need to update the status of ClusterwidePolicies resource and not
		// CiliumNetworkPolicy
		if ns == "" {
			_, err = client.CiliumV2().CiliumClusterwideNetworkPolicies().Patch(
				context.TODO(),
				name,
				k8sTypes.JSONPatchType,
				createStatusAndNodePatchJSON,
				metav1.PatchOptions{},
				"status",
			)
		} else {
			_, err = client.CiliumV2().CiliumNetworkPolicies(ns).Patch(
				context.TODO(),
				name,
				k8sTypes.JSONPatchType,
				createStatusAndNodePatchJSON,
				metav1.PatchOptions{},
				"status",
			)
		}

		if err != nil {
			// If there are more than MaxJSONPatchOperations to patch, do
			// multiple patches until we have removed all nodes from the set to
			// update.
			for len(nodeStatuses) != 0 {
				var (
					nodeNamesUsed            []string
					numPatches               int
					createStatusAndNodePatch []JSONPatch
				)

				// Reduce reallocations for slices.
				if len(nodeStatuses) <= MaxJSONPatchOperations {
					createStatusAndNodePatch = make([]JSONPatch, 0, len(nodeStatuses))
				} else {
					createStatusAndNodePatch = make([]JSONPatch, 0, MaxJSONPatchOperations)
				}

				for nodeName, nodeStatus := range nodeStatuses {

					if numPatches > MaxJSONPatchOperations {
						break
					}
					nodePatch := JSONPatch{
						OP:    "replace",
						Path:  "/status/nodes/" + nodeName,
						Value: nodeStatus,
					}
					createStatusAndNodePatch = append(createStatusAndNodePatch, nodePatch)
					numPatches += 1
					// Track which names we've used to delete them from the map
					// if patching succeeds later.
					nodeNamesUsed = append(nodeNamesUsed, nodeName)
				}
				createStatusAndNodePatchJSON, err = json.Marshal(createStatusAndNodePatch)
				if err != nil {
					return err
				}

				// Again for clusterwide policy we need to handle the update appropriately.
				if ns == "" {
					_, err = client.CiliumV2().CiliumClusterwideNetworkPolicies().Patch(
						context.TODO(),
						name,
						k8sTypes.JSONPatchType,
						createStatusAndNodePatchJSON,
						metav1.PatchOptions{},
						"status",
					)
				} else {
					_, err = client.CiliumV2().CiliumNetworkPolicies(ns).Patch(
						context.TODO(),
						name,
						k8sTypes.JSONPatchType,
						createStatusAndNodePatchJSON,
						metav1.PatchOptions{},
						"status",
					)
				}

				if err != nil {
					break
				}

				// Patch succeeded, we can remove from the set of NodeStatuses
				// to update.
				for _, nodeName := range nodeNamesUsed {
					delete(nodeStatuses, nodeName)
				}
			}
		}
	case capabilities.UpdateStatus:
		if cnp == nil {
			return fmt.Errorf("cannot update status of nil CNP")
		}
		// k8s < 1.13 has minimal support for JSON patch where kube-apiserver
		// can print Error messages and even panic in k8s < 1.10.
		for nodeName, cnpns := range nodeStatuses {
			cnp.SetPolicyStatus(nodeName, cnpns)
		}

		if ns == "" {
			ccnp := &cilium_v2.CiliumClusterwideNetworkPolicy{
				CiliumNetworkPolicy: cnp.CiliumNetworkPolicy,
				Status:              cnp.CiliumNetworkPolicy.Status,
			}
			_, err = client.CiliumV2().CiliumClusterwideNetworkPolicies().UpdateStatus(context.TODO(), ccnp, metav1.UpdateOptions{})
		} else {
			_, err = client.CiliumV2().CiliumNetworkPolicies(ns).UpdateStatus(context.TODO(), cnp.CiliumNetworkPolicy, metav1.UpdateOptions{})
		}

	default:
		if cnp == nil {
			return fmt.Errorf("cannot update status of nil CNP")
		}
		// k8s < 1.13 has minimal support for JSON patch where kube-apiserver
		// can print Error messages and even panic in k8s < 1.10.
		for nodeName, cnpns := range nodeStatuses {
			cnp.SetPolicyStatus(nodeName, cnpns)
		}

		if ns == "" {
			ccnp := &cilium_v2.CiliumClusterwideNetworkPolicy{
				CiliumNetworkPolicy: cnp.CiliumNetworkPolicy,
				Status:              cnp.CiliumNetworkPolicy.Status,
			}
			_, err = client.CiliumV2().CiliumClusterwideNetworkPolicies().UpdateStatus(context.TODO(), ccnp, metav1.UpdateOptions{})
		} else {
			_, err = client.CiliumV2().CiliumNetworkPolicies(ns).UpdateStatus(context.TODO(), cnp.CiliumNetworkPolicy, metav1.UpdateOptions{})
		}
	}
	if err != nil {
		return err
	}
	// Updating succeeded - the updated map can be 'emptied' of updates that
	// we need to propagate.
	for k := range nodeStatuses {
		delete(nodeStatuses, k)
	}
	return nil
}
