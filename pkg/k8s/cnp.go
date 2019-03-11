// Copyright 2016-2019 Authors of Cilium
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
	"time"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

var (
	ciliumPatchStatusVerConstr  = versioncheck.MustCompile(">= 1.13.0")
	ciliumUpdateStatusVerConstr = versioncheck.MustCompile(">= 1.11.0")
)

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

	// K8sServerVer is the Kubernetes apiserver version
	K8sServerVer *go_version.Version

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
func (c *CNPStatusUpdateContext) getUpdatedCNPFromStore(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	serverRuleStore, exists, err := c.CiliumV2Store.Get(cnp)
	if err != nil {
		return nil, fmt.Errorf("unable to find v2.CiliumNetworkPolicy in local cache: %s", err)
	}
	if !exists {
		return nil, errors.New("v2.CiliumNetworkPolicy does not exist in local cache")
	}

	serverRule, ok := serverRuleStore.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		return nil, errors.New("Received object of unknown type from API server, expecting v2.CiliumNetworkPolicy")
	}

	return serverRule, nil
}

// UpdateStatus updates the status section of a CiliumNetworkPolicy. It will
// retry as long as required to update the status unless a non-temporary error
// occurs in which case it expects a surrounding controller to restart or give
// up.
func (c *CNPStatusUpdateContext) UpdateStatus(ctx context.Context, cnp *cilium_v2.CiliumNetworkPolicy, rev uint64, policyImportErr error) error {
	var (
		updateWaitDuration       = time.Duration(200) * time.Millisecond
		overallErr, cnpUpdateErr error

		// Number of attempts to retry updating of CNP in case that Update fails
		// due to out-of-date resource version.
		maxAttempts = 5

		scopedLog = log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
		})
	)

	ctxEndpointWait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	waitForEPsErr := c.WaitForEndpointsAtPolicyRev(ctxEndpointWait, rev)

	for numAttempts := 0; numAttempts < maxAttempts; numAttempts++ {
		select {
		case <-ctx.Done():
			// The owning controller wants us to stop, no error is
			// returned. This is graceful
			return nil
		default:
		}

		var serverRuleCpy *cilium_v2.CiliumNetworkPolicy
		var ruleCopyParseErr error
		if c.CiliumV2Store != nil {
			serverRule, fromStoreErr := c.getUpdatedCNPFromStore(cnp)
			if fromStoreErr != nil {
				log.WithError(fromStoreErr).Debug("error getting updated CNP from store")
				return fromStoreErr
			}

			// Make a copy since the rule is a pointer, and any of its fields
			// which are also pointers could be modified outside of this
			// function.
			serverRuleCpy = serverRule.DeepCopy()
			_, ruleCopyParseErr = serverRuleCpy.Parse()
			if ruleCopyParseErr != nil {
				// If we can't parse the rule then we should signalize
				// it in the status
				log.WithError(ruleCopyParseErr).WithField(logfields.Object, logfields.Repr(serverRuleCpy)).
					Warn("Error parsing new CiliumNetworkPolicy rule")
			}

			scopedLog.WithField("cnpFromStore", serverRuleCpy.String()).Debug("copy of CNP retrieved from store which is being updated with status")
		} else {
			serverRuleCpy = cnp
			_, ruleCopyParseErr = cnp.Parse()
		}

		// Update the status of whether the rule is enforced on this node.
		// If we are unable to parse the CNP retrieved from the store,
		// or if endpoints did not reach the desired policy revision
		// after 30 seconds, then mark the rule as not being enforced.
		if policyImportErr != nil {
			// OK is false here because the policy wasn't imported into
			// cilium on this node; since it wasn't imported, it also
			// isn't enforced.
			cnpUpdateErr = c.update(serverRuleCpy, false, false, policyImportErr, rev, serverRuleCpy.Annotations)
		} else if ruleCopyParseErr != nil {
			// This handles the case where the initial instance of this
			// rule was imported into the policy repository successfully
			// (policyImportErr == nil), but, the rule has been updated
			// in the store soon after, and is now invalid. As such,
			// the rule is not OK because it cannot be imported due
			// to parsing errors, and cannot be enforced because it is
			// not OK.
			cnpUpdateErr = c.update(serverRuleCpy, false, false, ruleCopyParseErr, rev, serverRuleCpy.Annotations)
		} else {
			// If the deadline by the above context, then not all
			// endpoints are enforcing the given policy, and
			// waitForEpsErr will be non-nil.
			cnpUpdateErr = c.update(serverRuleCpy, waitForEPsErr == nil, true, waitForEPsErr, rev, serverRuleCpy.Annotations)
		}

		if cnpUpdateErr == nil {
			scopedLog.WithField("status", serverRuleCpy.Status).Debug("successfully updated with status")
			break
		}

		scopedLog.WithError(cnpUpdateErr).Debugf("Update of CNP status failed. Sleeping for %s before retrying", updateWaitDuration)
		time.Sleep(updateWaitDuration)
	}

	if cnpUpdateErr != nil {
		overallErr = cnpUpdateErr
	} else {
		overallErr = waitForEPsErr
	}

	if overallErr != nil {
		scopedLog.WithError(overallErr).Warningf("Update of CNP status failed %d times. Will keep retrying.", maxAttempts)
	}

	return overallErr
}

type jsonPatch struct {
	OP    string      `json:"op,omitempty"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value"`
}

func (c *CNPStatusUpdateContext) update(cnp *cilium_v2.CiliumNetworkPolicy, enforcing, ok bool, cnpError error, rev uint64, annotations map[string]string) error {
	var (
		cnpns cilium_v2.CiliumNetworkPolicyNodeStatus
		err   error
	)

	if cnpError != nil {
		cnpns = cilium_v2.CiliumNetworkPolicyNodeStatus{
			Enforcing:   enforcing,
			Error:       cnpError.Error(),
			OK:          ok,
			LastUpdated: cilium_v2.NewTimestamp(),
			Annotations: annotations,
		}
	} else {
		cnpns = cilium_v2.CiliumNetworkPolicyNodeStatus{
			Enforcing:   enforcing,
			Revision:    rev,
			OK:          ok,
			LastUpdated: cilium_v2.NewTimestamp(),
			Annotations: annotations,
		}
	}

	ns := k8sUtils.ExtractNamespace(&cnp.ObjectMeta)

	switch {
	case ciliumPatchStatusVerConstr.Check(c.K8sServerVer):
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
		createStatusAndNodePatch := []jsonPatch{
			{
				OP:    "test",
				Path:  "/status",
				Value: nil,
			},
			{
				OP:   "add",
				Path: "/status",
				Value: cilium_v2.CiliumNetworkPolicyStatus{
					Nodes: map[string]cilium_v2.CiliumNetworkPolicyNodeStatus{
						c.NodeName: cnpns,
					},
				},
			},
		}

		var createStatusAndNodePatchJSON []byte
		createStatusAndNodePatchJSON, err = json.Marshal(createStatusAndNodePatch)
		if err != nil {
			return err
		}

		_, err = c.CiliumNPClient.CiliumV2().CiliumNetworkPolicies(ns).Patch(cnp.GetName(), types.JSONPatchType, createStatusAndNodePatchJSON, "status")
		if err != nil {
			// If it fails it means the test from the previous patch failed
			// so we can safely replace this node in the CNP status.
			createStatusAndNodePatch := []jsonPatch{
				{
					OP:    "replace",
					Path:  "/status/nodes/" + c.NodeName,
					Value: cnpns,
				},
			}
			createStatusAndNodePatchJSON, err = json.Marshal(createStatusAndNodePatch)
			if err != nil {
				return err
			}
			_, err = c.CiliumNPClient.CiliumV2().CiliumNetworkPolicies(ns).Patch(cnp.GetName(), types.JSONPatchType, createStatusAndNodePatchJSON, "status")
		}
	case ciliumUpdateStatusVerConstr.Check(c.K8sServerVer):
		// k8s < 1.13 as minimal support for JSON patch where kube-apiserver
		// can print Error messages and even panic in k8s < 1.10.
		cnp.SetPolicyStatus(c.NodeName, cnpns)
		_, err = c.CiliumNPClient.CiliumV2().CiliumNetworkPolicies(ns).UpdateStatus(cnp)
	default:
		// k8s < 1.13 as minimal support for JSON patch where kube-apiserver
		// can print Error messages and even panic in k8s < 1.10.
		cnp.SetPolicyStatus(c.NodeName, cnpns)
		_, err = c.CiliumNPClient.CiliumV2().CiliumNetworkPolicies(ns).Update(cnp)
	}
	return err
}
