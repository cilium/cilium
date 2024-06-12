// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/redirectpolicy"
)

type k8sCiliumLRPWatcherParams struct {
	cell.In

	K8sEventReporter *K8sEventReporter

	Clientset         k8sClient.Clientset
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups

	LRPManager *redirectpolicy.Manager
}

func newK8sCiliumLRPWatcher(params k8sCiliumLRPWatcherParams) *K8sCiliumLRPWatcher {
	return &K8sCiliumLRPWatcher{
		clientset:             params.Clientset,
		k8sEventReporter:      params.K8sEventReporter,
		k8sResourceSynced:     params.K8sResourceSynced,
		k8sAPIGroups:          params.K8sAPIGroups,
		redirectPolicyManager: params.LRPManager,
		stop:                  make(chan struct{}),
	}
}

type K8sCiliumLRPWatcher struct {
	clientset k8sClient.Clientset

	k8sEventReporter *K8sEventReporter

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups

	redirectPolicyManager redirectPolicyManager

	stop chan struct{}
}

func (k *K8sCiliumLRPWatcher) ciliumLocalRedirectPolicyInit() {
	apiGroup := k8sAPIGroupCiliumLocalRedirectPolicyV2
	_, lrpController := informer.NewInformer(
		cache.NewListWatchFromClient(k.clientset.CiliumV2().RESTClient(),
			"ciliumlocalredirectpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumLocalRedirectPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.k8sEventReporter.K8sEventReceived(apiGroup, metricCLRP, resources.MetricCreate, valid, equal)
				}()
				if cLRP := k8s.CastInformerEvent[cilium_v2.CiliumLocalRedirectPolicy](obj); cLRP != nil {
					valid = true
					err := k.addCiliumLocalRedirectPolicy(cLRP)
					k.k8sEventReporter.K8sEventProcessed(metricCLRP, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.Info("Local Redirect Policy updates are not handled")
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.k8sEventReporter.K8sEventReceived(apiGroup, metricCLRP, resources.MetricDelete, valid, equal)
				}()
				cLRP := k8s.CastInformerEvent[cilium_v2.CiliumLocalRedirectPolicy](obj)
				if cLRP == nil {
					return
				}
				valid = true
				err := k.deleteCiliumLocalRedirectPolicy(cLRP)
				k.k8sEventReporter.K8sEventProcessed(metricCLRP, resources.MetricDelete, err == nil)
			},
		},
		nil,
	)

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		k.stop,
		nil,
		lrpController.HasSynced,
		k8sAPIGroupCiliumLocalRedirectPolicyV2,
	)

	go lrpController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumLocalRedirectPolicyV2)
}

func (k *K8sCiliumLRPWatcher) stopWatcher() {
	close(k.stop)
}

func (k *K8sCiliumLRPWatcher) addCiliumLocalRedirectPolicy(clrp *cilium_v2.CiliumLocalRedirectPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumLocalRedirectName: clrp.ObjectMeta.Name,
		logfields.K8sUID:                  clrp.ObjectMeta.UID,
		logfields.K8sAPIVersion:           clrp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            clrp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Add CiliumLocalRedirectPolicy")

	rp, policyAddErr := redirectpolicy.Parse(clrp, true)
	if policyAddErr == nil {
		_, policyAddErr = k.redirectPolicyManager.AddRedirectPolicy(*rp)
	}

	if policyAddErr != nil {
		scopedLog.WithError(policyAddErr).Warn("Failed to add CiliumLocalRedirectPolicy")
	} else {
		scopedLog.Info("Added CiliumLocalRedirectPolicy")
	}

	// TODO update status

	return policyAddErr
}

func (k *K8sCiliumLRPWatcher) deleteCiliumLocalRedirectPolicy(clrp *cilium_v2.CiliumLocalRedirectPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumLocalRedirectName: clrp.ObjectMeta.Name,
		logfields.K8sUID:                  clrp.ObjectMeta.UID,
		logfields.K8sAPIVersion:           clrp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            clrp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Delete CiliumLocalRedirectPolicy")

	rp, policyDelErr := redirectpolicy.Parse(clrp, false)
	if policyDelErr == nil {
		policyDelErr = k.redirectPolicyManager.DeleteRedirectPolicy(*rp)
	}

	if policyDelErr != nil {
		scopedLog.WithError(policyDelErr).Warn("Failed to delete CiliumLocalRedirectPolicy")
	} else {
		scopedLog.Info("Deleted CiliumLocalRedirectPolicy")
	}

	return policyDelErr
}
