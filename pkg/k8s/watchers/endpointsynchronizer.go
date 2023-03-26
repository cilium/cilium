// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// subsysEndpointSync is the value for logfields.LogSubsys
	subsysEndpointSync = "endpointsynchronizer"
)

// EndpointSynchronizer currently is an empty type, which wraps around syncing
// of CiliumEndpoint resources.
type EndpointSynchronizer struct {
	Clientset client.Clientset
}

// RunK8sCiliumEndpointSync starts a controller that synchronizes the endpoint
// to the corresponding k8s CiliumEndpoint CRD. It is expected that each CEP
// has 1 controller that updates it, and a local copy is retained and only
// updates are pushed up.
// CiliumEndpoint objects have the same name as the pod they represent.
func (epSync *EndpointSynchronizer) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration) {
	var (
		endpointID     = e.ID
		controllerName = endpoint.EndpointSyncControllerName(endpointID)
		scopedLog      = e.Logger(subsysEndpointSync).WithFields(logrus.Fields{
			"controller": controllerName,
			"endpointID": e.ID,
		})
	)

	if option.Config.DisableCiliumEndpointCRD {
		scopedLog.Debug("Not running controller. CEP CRD synchronization is disabled")
		return
	}

	if !epSync.Clientset.IsEnabled() {
		scopedLog.Debug("Not starting controller because k8s is disabled")
		return
	}

	ciliumClient := epSync.Clientset.CiliumV2()

	// The health endpoint doesn't really exist in k8s and updates to it caused
	// arbitrary errors. Disable the controller for these endpoints.
	if isHealthEP := e.HasLabels(pkgLabels.LabelHealth); isHealthEP {
		scopedLog.Debug("Not starting unnecessary CEP controller for cilium-health endpoint")
		return
	}

	var (
		lastMdl  *cilium_v2.EndpointStatus
		localCEP *cilium_v2.CiliumEndpoint // the local copy of the CEP object. Reused.
		needInit = true                    // needInit indicates that we may need to create the CEP
		firstTry = true                    // Try to get CEP from k8s cache
	)

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 10 * time.Second,
			DoFunc: func(ctx context.Context) (err error) {
				// Update logger as scopeLog might not have the podName when it
				// was created.
				scopedLog = e.Logger(subsysEndpointSync).WithField("controller", controllerName)

				if k8sversion.Version().Equals(semver.Version{}) {
					return fmt.Errorf("Kubernetes apiserver is not available")
				}

				// K8sPodName and K8sNamespace are not always available when an
				// endpoint is first created, so we collect them here.
				podName := e.GetK8sPodName()
				if podName == "" {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s pod name")
					return nil
				}

				namespace := e.GetK8sNamespace()
				if namespace == "" {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s namespace")
					return nil
				}

				if !e.HaveK8sMetadata() {
					scopedLog.Debug("Skipping CiliumEndpoint update because k8s metadata is not yet available")
					return nil
				}

				identity, err := e.GetSecurityIdentity()
				if err != nil {
					return err
				}
				if identity == nil {
					scopedLog.Debug("Skipping CiliumEndpoint update because security identity is not yet available")
					return nil
				}

				// Serialize the endpoint into a model. It is compared with the one
				// from before, only updating on changes.
				mdl := e.GetCiliumEndpointStatus(conf)
				if !needInit && mdl.DeepEqual(lastMdl) {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has not changed")
					return nil
				}

				if needInit {
					state := e.GetState()
					// Don't bother to create if the
					// endpoint is already disconnecting
					if state == endpoint.StateDisconnecting ||
						state == endpoint.StateDisconnected {
						return nil
					}

					scopedLog.Debug("Getting CEP during an initialization")
					if firstTry {
						// First we try getting CEP from the API server cache, as it's cheaper.
						// If it fails we get it from etcd to be sure to have fresh data.
						localCEP, err = ciliumClient.CiliumEndpoints(namespace).Get(ctx, podName, meta_v1.GetOptions{ResourceVersion: "0"})
						firstTry = false
					} else {
						localCEP, err = ciliumClient.CiliumEndpoints(namespace).Get(ctx, podName, meta_v1.GetOptions{})
					}
					// It's only an error if it exists but something else happened
					switch {
					case err == nil:
						// Backfill the CEP UID as we need to do if the CEP was
						// created on an agent version that did not yet store the
						// UID at CEP create time.
						if err := updateCEPUID(scopedLog, e, localCEP); err != nil {
							scopedLog.WithError(err).Warn("could not take ownership of existing ciliumendpoint")
							return err
						}
					case k8serrors.IsNotFound(err):
						pod := e.GetPod()
						if pod == nil {
							scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s pod")
							return nil
						}

						// We can't create localCEP directly, it must come from the k8s
						// server via an API call.
						cep := &cilium_v2.CiliumEndpoint{
							ObjectMeta: meta_v1.ObjectMeta{
								Name: podName,
								OwnerReferences: []meta_v1.OwnerReference{
									{
										APIVersion: "v1",
										Kind:       "Pod",
										Name:       pod.GetObjectMeta().GetName(),
										UID:        pod.ObjectMeta.UID,
									},
								},
								// Mirror the labels of parent pod in CiliumEndpoint object to enable
								// label based selection for CiliumEndpoints.
								Labels: pod.GetObjectMeta().GetLabels(),
							},
							Status: *mdl,
						}
						localCEP, err = ciliumClient.CiliumEndpoints(namespace).Create(ctx, cep, meta_v1.CreateOptions{})
						if err != nil {
							// Suppress logging an error if ep backing the pod was terminated
							// before CEP could be created and shut down the controller.
							if errors.Is(err, context.Canceled) {
								return nil
							}

							scopedLog.WithError(err).Error("Cannot create CEP")
							return err
						}

						scopedLog.WithField(logfields.CEPUID, localCEP.UID).Debug("storing CEP UID after create")
						e.SetCiliumEndpointUID(localCEP.UID)

						// continue the execution so we update the endpoint
						// status immediately upon endpoint creation
					default:
						scopedLog.WithError(err).Warn("Error getting CEP")
						return err
					}

					// We return earlier for all error cases so we don't need
					// to init the local endpoint in non-error cases.
					needInit = false
					lastMdl = &localCEP.Status
					// We still need to update the CEP if localCEP is out of sync with upstream.
					// We only return if upstream is NOT out-of-sync here.
					if mdl.DeepEqual(lastMdl) {
						scopedLog.Debug("Skipping CiliumEndpoint update because it has not changed")
						return nil
					}
				}
				// We have no localCEP copy. We need to fetch it for updates, below.
				// This is unexpected as there should be only 1 writer per CEP, this
				// controller, and the localCEP created on startup will be used.
				if localCEP == nil {
					localCEP, err = ciliumClient.CiliumEndpoints(namespace).Get(ctx, podName, meta_v1.GetOptions{})
					switch {
					case err == nil:
						// Backfill the CEP UID as we need to do if the CEP was
						// created on an agent version that did not yet store the
						// UID at CEP create time.
						if err := updateCEPUID(scopedLog, e, localCEP); err != nil {
							scopedLog.WithError(err).Warn("could not take ownership of existing ciliumendpoint")
							return err
						}

					// The CEP doesn't exist in k8s. This is unexpetected but may occur
					// if the endpoint was removed from k8s but not yet within the agent.
					// Mark the CEP for creation on the next controller iteration. This
					// may never occur if the controller is stopped on Endpoint delete.
					case k8serrors.IsNotFound(err):
						needInit = true
						return err

					// We cannot read the upstream CEP. needInit will cause the next
					// iteration to delete and create the CEP. This is an unexpected
					// situation.
					case k8serrors.IsInvalid(err):
						scopedLog.WithError(err).Warn("Invalid CEP during update")
						needInit = true
						return nil

					// A real error
					default:
						scopedLog.WithError(err).Error("Cannot get CEP during update")
						return err
					}
				}

				// For json patch we don't need to perform a GET for endpoints

				// If it fails it means the test from the previous patch failed
				// so we can safely replace this node in the CNP status.
				replaceCEPStatus := []k8s.JSONPatch{
					// If the stored UID matches the one in the ciliumendpoint then
					// this first patch is a no-op, otherwise the entire patch will
					// not be applied as uid is immutable.
					{
						OP:    "test",
						Path:  "/metadata/uid",
						Value: e.GetCiliumEndpointUID(),
					},
					{
						OP:    "replace",
						Path:  "/status",
						Value: mdl,
					},
				}
				var createStatusPatch []byte
				createStatusPatch, err = json.Marshal(replaceCEPStatus)
				if err != nil {
					return err
				}

				localCEP, err = ciliumClient.CiliumEndpoints(namespace).Patch(
					ctx, podName,
					k8stypes.JSONPatchType,
					createStatusPatch,
					meta_v1.PatchOptions{})

				// Handle Update errors or return successfully
				switch {
				// Return no error when we see a conflict. We want to retry without a
				// backoff and the Update* calls returned the current localCEP
				case err != nil && k8serrors.IsConflict(err):
					scopedLog.WithError(err).Warn("Cannot update CEP due to a revision conflict. The next controller execution will try again")
					needInit = true
					return nil

				// Ensure we re-init when we see a generic error. This will recrate the
				// CEP.
				case err != nil:
					// Suppress logging an error if ep backing the pod was terminated
					// before CEP could be updated and shut down the controller.
					if errors.Is(err, context.Canceled) {
						return nil
					}
					scopedLog.WithError(err).Error("Cannot update CEP")

					needInit = true
					return err

				// A successful update means no more updates unless the endpoint status, aka mdl, changes
				default:
					lastMdl = mdl
					return nil
				}
			},
			StopFunc: func(ctx context.Context) error {
				return deleteCEP(ctx, scopedLog, ciliumClient, e)
			},
		})
}

// updateCEPUID attempts to update the endpoints UID to be that of localCEP.
// This in effect takes ownership of the referenced CEP, thus we can only
// do this if it is safe to do so. Otherwise an error is returned.
//
// One caveat is that, although endpoints are now restored to reference their
// previous CEP, this has to handle cases where agent was upgraded from a version
// that did not store CEP UIDs in the restore state header.
// It is only safe to do so if the CEP is local.
//
// In all cases where the endpoint cannot take ownership of a CEP, it is assumed
// that this is a temporary state where either the local/remote agent managing the CEP
// is shutting down and will delete the CEP, or the CEP is stale and needs to be cleaned
// up by the operator.
func updateCEPUID(scopedLog *logrus.Entry, e *endpoint.Endpoint, localCEP *cilium_v2.CiliumEndpoint) error {
	// It's possible we already own this CEP, as in the case of a restore after restart.
	// If the Endpoint already owns the CEP (by holding the matching CEP UID reference) then we don't have to
	// worry about other ownership checks.
	//
	// This will cover cases such as if the NodeIP changes (as with a reboot). In which case we can safely
	// take ownership and overwrite the CEPs status.
	cepUID := e.GetCiliumEndpointUID()
	if cepUID == localCEP.UID {
		return nil
	}

	var nodeIP string
	if netStatus := localCEP.Status.Networking; netStatus == nil {
		return fmt.Errorf("endpoint sync cannot take ownership of CEP that has no nodeIP status")
	} else {
		nodeIP = netStatus.NodeIP
	}

	// We do not want to take ownership of CEPs created on other Nodes.
	if nodeIP != node.GetCiliumEndpointNodeIP() {
		return fmt.Errorf("endpoint sync cannot take ownership of CEP that is not local (%q)", nodeIP)
	}

	// If the endpoint has a CEP UID, which does not match the current CEP, we cannot take
	// ownership.
	if cepUID != "" && cepUID != localCEP.GetUID() {
		return fmt.Errorf("endpoint sync could not take ownership of CEP %q, endpoint UID (%q) did not match CEP UID: %q",
			localCEP.GetNamespace()+"/"+localCEP.GetName(), cepUID, localCEP.GetUID())
	}

	if cepUID := e.GetCiliumEndpointUID(); cepUID == "" {
		scopedLog.WithFields(logrus.Fields{
			logfields.Node:           types.GetName(),
			"old" + logfields.CEPUID: cepUID,
			logfields.CEPUID:         localCEP.UID,
		}).Debug("updating CEP UID and syncing endpoint header file")
		e.SetCiliumEndpointUID(localCEP.UID)
		e.SyncEndpointHeaderFile()
	}
	return nil
}

// DeleteK8sCiliumEndpointSync replaces the endpoint controller to remove the
// CEP from Kubernetes once the endpoint is stopped / removed from the
// Cilium agent.
func (epSync *EndpointSynchronizer) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
	controllerName := endpoint.EndpointSyncControllerName(e.ID)

	scopedLog := e.Logger(subsysEndpointSync).WithField("controller", controllerName)

	if !epSync.Clientset.IsEnabled() {
		scopedLog.Debug("Not starting controller because k8s is disabled")
		return
	}
	ciliumClient := epSync.Clientset.CiliumV2()

	// The health endpoint doesn't really exist in k8s and updates to it caused
	// arbitrary errors. Disable the controller for these endpoints.
	if isHealthEP := e.HasLabels(pkgLabels.LabelHealth); isHealthEP {
		scopedLog.Debug("Not starting unnecessary CEP controller for cilium-health endpoint")
		return
	}

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.UpdateController(controllerName,
		controller.ControllerParams{
			StopFunc: func(ctx context.Context) error {
				return deleteCEP(ctx, scopedLog, ciliumClient, e)
			},
		},
	)
}

func deleteCEP(ctx context.Context, scopedLog *logrus.Entry, ciliumClient v2.CiliumV2Interface, e *endpoint.Endpoint) error {
	podName := e.GetK8sPodName()
	if podName == "" {
		scopedLog.Debug("Skipping CiliumEndpoint deletion because it has no k8s pod name")
		return nil
	}
	namespace := e.GetK8sNamespace()
	if namespace == "" {
		scopedLog.Debug("Skipping CiliumEndpoint deletion because it has no k8s namespace")
		return nil
	}

	// A CEP should be only be deleted by the agent that manages the
	// corresponding pod. However, it is possible for a pod to restart and be
	// scheduled onto a different node while the agent on the original node was
	// down, which would cause the CEP to be deleted once the original agent came
	// back up. (This holds for StatefulSets in particular that come with stable
	// pod identifiers and thus do not guard against such accidental deletes
	// through unique pod names.) Storing the CEP UID at CEP create/fetch time
	// and using it as a precondition for deletion ensures that agents may only
	// delete CEPs they own.
	// It is possible for the CEP UID to not be populated when an agent tries to
	// clean up a CEP. In that case, skip deletion and rely on cilium operator
	// garbage collection to clean up eventually.
	cepUID := e.GetCiliumEndpointUID()
	if cepUID == "" {
		scopedLog.Debug("Skipping CiliumEndpoint deletion because it has no UID")
		return nil
	}

	scopedLog.WithField(logfields.CEPUID, cepUID).Debug("deleting CEP with UID")
	if err := ciliumClient.CiliumEndpoints(namespace).Delete(ctx, podName, meta_v1.DeleteOptions{
		Preconditions: &meta_v1.Preconditions{
			UID: &cepUID,
		},
	}); err != nil {
		if !k8serrors.IsNotFound(err) && !k8serrors.IsConflict(err) {
			scopedLog.WithError(err).Warning("Unable to delete CEP")
		}
	}
	return nil
}
