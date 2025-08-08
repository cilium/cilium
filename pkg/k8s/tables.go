// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var (
	// Services is a table of Kubernetes services.
	Services      statedb.Table[*slim_corev1.Service]
	servicesTable statedb.RWTable[*slim_corev1.Service]
)

func init() {
	var err error
	servicesTable, err = statedb.NewTable(
		"k8s-services",
		statedb.Index[*slim_corev1.Service, string]{
			Name: "namespace-name",
			FromObject: func(obj *slim_corev1.Service) index.KeySet {
				return index.NewKeySet(index.String(obj.Namespace + "/" + obj.Name))
			},
			FromKey: index.String,
			Unique:  true,
		},
	)
	if err != nil {
		panic(err)
	}
	Services = servicesTable
}
