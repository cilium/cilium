// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/resiliency"
)

type localEndpointCache interface {
	LookupCEPName(namespacedName string) *endpoint.Endpoint
}

// This must only be run after K8s Pod and CES/CEP caches are synced and local endpoint restoration is complete.
func (d *Daemon) cleanStaleCEPs(ctx context.Context, eps localEndpointCache, ciliumClient ciliumv2.CiliumV2Interface, enableCiliumEndpointSlice bool) error {
	crdType := "ciliumendpoint"
	if enableCiliumEndpointSlice {
		crdType = "ciliumendpointslice"
	}
	indexer := d.k8sWatcher.GetIndexer(crdType)
	if indexer == nil {
		return fmt.Errorf("%s indexer was nil", crdType)
	}
	objs, err := indexer.ByIndex("localNode", node.GetCiliumEndpointNodeIP())
	if err != nil {
		return fmt.Errorf("could not get %s objects from localNode indexer: %w", crdType, err)
	}

	var errs error
	if enableCiliumEndpointSlice {
		for _, cesObj := range objs {
			ces, ok := cesObj.(*cilium_v2a1.CiliumEndpointSlice)
			if !ok {
				return fmt.Errorf("unexpected object type returned from ciliumendpointslice store: %T", cesObj)
			}
			for _, cep := range ces.Endpoints {
				if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() && eps.LookupCEPName(ces.Namespace+"/"+cep.Name) == nil {
					if err := d.deleteCiliumEndpoint(ctx, ces.Namespace, cep.Name, nil, ciliumClient, eps, enableCiliumEndpointSlice); err != nil {
						errs = errors.Join(errs, err)
					}
				}
			}
		}
	} else {
		for _, cepObj := range objs {
			cep, ok := cepObj.(*types.CiliumEndpoint)
			if !ok {
				return fmt.Errorf("unexpected object type returned from ciliumendpoint store: %T", cepObj)
			}
			if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() && eps.LookupCEPName(cep.Namespace+"/"+cep.Name) == nil {
				if err := d.deleteCiliumEndpoint(ctx, cep.Namespace, cep.Name, &cep.ObjectMeta.UID, ciliumClient, eps, enableCiliumEndpointSlice); err != nil {
					errs = errors.Join(errs, err)
				}
			}
		}
	}

	return errs
}

// deleteCiliumEndpoint safely deletes a CEP by name, if no UID is passed this will reverify that
// the CEP is still local before doing a delete.
func (d *Daemon) deleteCiliumEndpoint(
	ctx context.Context,
	cepNamespace,
	cepName string,
	cepUID *apiTypes.UID,
	ciliumClient ciliumv2.CiliumV2Interface,
	eps localEndpointCache,
	endpointSliceEnabled bool) error {
	// To avoid having to store CEP UIDs in CES Endpoints array, we have to get the latest
	// referenced CEP from apiserver to verify that it still references this node.
	// To avoid excessive api calls, we only do this if CES is enabled and the CEP
	// appears to be stale.
	if cepUID == nil && endpointSliceEnabled {
		cep, err := ciliumClient.CiliumEndpoints(cepNamespace).Get(ctx, cepName, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				log.WithError(err).WithFields(logrus.Fields{logfields.CEPName: cepName, logfields.K8sNamespace: cepNamespace}).
					Info("CEP no longer exists, skipping staleness check")
				return nil
			}
			log.WithError(err).WithFields(logrus.Fields{logfields.CEPName: cepName, logfields.K8sNamespace: cepNamespace}).
				Error("Failed to get possibly stale ciliumendpoints from apiserver")
			return resiliency.NewRetryableErr(err)
		}
		if cep.Status.Networking.NodeIP != node.GetCiliumEndpointNodeIP() {
			log.WithError(err).WithFields(logrus.Fields{logfields.CEPName: cepName, logfields.K8sNamespace: cepNamespace}).
				Debug("Stale CEP fetched apiserver no longer references this Node, skipping.")
			return nil
		}
		cepUID = &cep.ObjectMeta.UID
	}
	// There exists a local CiliumEndpoint that is not in the endpoint manager.
	// This function is run after completing endpoint restoration from local state and K8s cache sync.
	// Therefore, we can delete the CiliumEndpoint as it is not referencing a Pod that is being managed.
	// This may occur for various reasons:
	// * Pod was restarted while Cilium was not running (likely prior to CNI conf being installed).
	// * Local endpoint was deleted (i.e. due to reboot + temporary filesystem) and Cilium or the Pod where restarted.
	log.WithFields(logrus.Fields{
		logfields.CEPName:      cepName,
		logfields.K8sNamespace: cepNamespace,
	}).Info("Found stale ciliumendpoint for local pod that is not being managed, deleting.")
	if err := ciliumClient.CiliumEndpoints(cepNamespace).Delete(ctx, cepName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID: cepUID,
		},
	}); err != nil {
		logger := log.WithError(err).WithFields(logrus.Fields{logfields.CEPName: cepName, logfields.K8sNamespace: cepNamespace})
		if k8serrors.IsNotFound(err) {
			// CEP not found, likely already deleted. Do not log as an error as that
			// will fail CI runs.
			logger.Debug("Could not delete stale CEP")
			return nil
		}
		logger.Error("Could not delete stale CEP")
		return resiliency.NewRetryableErr(err)
	}

	return nil
}
