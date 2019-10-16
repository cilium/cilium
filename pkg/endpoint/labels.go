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

package endpoint

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/controller"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

// K8sLabelFetcher is any function which retrieves the k8s labels and annotations
// for the specified Endpoint.
type K8sLabelFetcher func(ep *Endpoint) (labels.Labels, labels.Labels, map[string]string, error)

func (ep *Endpoint) PopulateLabels(templateLabels []string, k8sEnabled bool, lblFunc K8sLabelFetcher) (addLabels, infoLabels labels.Labels, err error) {
	addLabels = labels.NewLabelsFromModel(templateLabels)
	infoLabels = labels.NewLabelsFromModel([]string{})

	if len(addLabels) > 0 {
		if lbls := addLabels.FindReserved(); lbls != nil {
			return nil, nil, fmt.Errorf("not allowed to add reserved labels: %s", lbls)
		}

		addLabels, _, _ = labels.CheckLabels(addLabels, nil)
		if len(addLabels) == 0 {
			return nil, nil, fmt.Errorf("no valid labels provided")
		}
	}

	if ep.K8sNamespaceAndPodNameIsSet() && k8sEnabled {
		identityLabels, info, annotations, err := lblFunc(ep)
		if err != nil {
			ep.Logger("api").WithError(err).Warning("Unable to fetch kubernetes labels")
		} else {
			addLabels.MergeLabels(identityLabels)
			infoLabels.MergeLabels(info)
			ep.UpdateVisibilityPolicy(annotations[annotation.ProxyVisibility])
		}
	}

	if len(addLabels) == 0 {
		// If the endpoint has no labels, give the endpoint a special identity with
		// label reserved:init so we can generate a custom policy for it until we
		// get its actual identity.
		addLabels = labels.Labels{
			labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
		}
	}

	// Static pods (mirror pods) might be configured before the apiserver
	// is available or has received the notification that includes the
	// static pod's labels. In this case, start a controller to attempt to
	// resolve the labels.
	if ep.K8sNamespaceAndPodNameIsSet() && k8sEnabled {
		// If there are labels, but no pod namespace then it's
		// likely that there are no k8s labels at all. Resolve.
		if _, k8sLabelsConfigured := addLabels[k8sConst.PodNamespaceLabel]; !k8sLabelsConfigured {
			done := make(chan struct{})

			controllerName := fmt.Sprintf("resolve-labels-%s", ep.GetK8sNamespaceAndPodName())
			mgr := controller.NewManager()
			mgr.UpdateController(controllerName,
				controller.ControllerParams{
					DoFunc: func(ctx context.Context) error {
						identityLabels, info, annotations, err := lblFunc(ep)
						if err != nil {
							ep.Logger(controllerName).WithError(err).Warning("Unable to fetch kubernetes labels")
							return err
						}
						ep.UpdateVisibilityPolicy(annotations[annotation.ProxyVisibility])
						ep.UpdateLabels(ctx, identityLabels, info, true)
						close(done)
						return nil
					},
					RunInterval: 30 * time.Second,
				},
			)
			go func() {
				<-done
				mgr.RemoveController(controllerName)
			}()
		}
	}
	return addLabels, infoLabels, nil
}
