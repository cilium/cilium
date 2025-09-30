// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type Namespace struct {
	*slim_corev1.Namespace
	// Enrolled indicates if the namespace is enrolled for mTLS.
	Enrolled                     bool
	PendingEndpointEnrollment    bool              // PendingEndpointEnrollment indicates if there is a pending endpoint enrollment for the namespace.
	PendingEndpointDisenrollment bool              // PendingEndpointDisenrollment indicates if there is a pending endpoint disenrollment for the namespace.
	Status                       reconciler.Status // reconciliation status
}

// TableHeader implements statedb.TableWritable.
func (ns *Namespace) TableHeader() []string {
	return []string{"Name", "Enrolled for mTLS", "Pending Endpoint Enrollments", "Pending Endpoint Disenrollments", "Status"}
}

// TableRow implements statedb.TableWritable.
func (ns *Namespace) TableRow() []string {
	return []string{ns.Name, fmt.Sprintf("%t", ns.Enrolled), fmt.Sprintf("%t", ns.PendingEndpointEnrollment), fmt.Sprintf("%t", ns.PendingEndpointDisenrollment), ns.Status.String()}
}

var _ statedb.TableWritable = &Namespace{}

// GetStatus returns the reconciliation status. Used to provide the
// reconciler access to it.
func (ns Namespace) GetStatus() reconciler.Status {
	return ns.Status
}

// SetStatus sets the reconciliation status.
// Used by the reconciler to update the reconciliation status of the EnrolledNamespace.
func (ns *Namespace) SetStatus(status reconciler.Status) *Namespace {
	ns.Status = status
	return ns
}

// Clone returns a shallow copy of the EnrolledNamespace.
func (ns *Namespace) Clone() *Namespace {
	e := *ns
	return &e
}

// EnrolledNamespacesNameIndex allows looking up EnrolledNamespace by its name.
var EnrolledNamespacesNameIndex = statedb.Index[*Namespace, string]{
	Name: "name",
	FromObject: func(ns *Namespace) index.KeySet {
		return index.NewKeySet(index.String(ns.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

var EnrolledNamespacesStatusIndex = reconciler.NewStatusIndex((*Namespace).GetStatus)

func NewEnrolledNamespacesTable(jg job.Group, db *statedb.DB, cs client.Clientset) (statedb.RWTable[*Namespace], error) {
	enrolledNamespaces, err := statedb.NewTable(
		db,
		"namespaces",
		EnrolledNamespacesNameIndex,
		EnrolledNamespacesStatusIndex,
	)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return enrolledNamespaces, nil
	}

	cfg := namespaceReflectorConfig(cs, enrolledNamespaces)
	err = k8s.RegisterReflector(jg, db, cfg)
	return enrolledNamespaces, err
}

func namespaceReflectorConfig(cs client.Clientset, namespaces statedb.RWTable[*Namespace]) k8s.ReflectorConfig[*Namespace] {
	lw := utils.ListerWatcherFromTyped(cs.Slim().CoreV1().Namespaces())
	return k8s.ReflectorConfig[*Namespace]{
		Name:          "k8s-namespaces",
		Table:         namespaces,
		ListerWatcher: lw,
		MetricScope:   "Namespace",
		Transform: func(txn statedb.ReadTxn, obj any) (*Namespace, bool) {
			namespace, ok := obj.(*slim_corev1.Namespace)
			if !ok {
				return &Namespace{}, false
			}
			enrolled := true
			pendingEndpointEnrollment := true
			if mtlsValue, exists := namespace.Labels["mtls-enabled"]; !exists || mtlsValue != "true" {
				enrolled = false
				pendingEndpointEnrollment = false
			}
			pendingEndpointDisenrollment := false
			prevEntry, _, found := namespaces.Get(txn, EnrolledNamespacesNameIndex.Query(namespace.Name))
			// If the previous entry was enrolled and the new one is not, mark for pending CA deletion.
			if found && prevEntry.Enrolled && !enrolled {
				pendingEndpointDisenrollment = true
			}
			return &Namespace{
				Namespace:                    namespace,
				Enrolled:                     enrolled,
				PendingEndpointEnrollment:    pendingEndpointEnrollment,
				PendingEndpointDisenrollment: pendingEndpointDisenrollment,
				Status:                       reconciler.StatusPending(),
			}, true
		},
	}
}
