// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

// LocalPod is Cilium's internal model of the pods running on this node.
type LocalPod struct {
	*slim_corev1.Pod

	// UpdatedAt is the time when [LocalPod] was last updated, e.g. it
	// shows when the pod change was received from the api-server.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`
}

func (p LocalPod) TableHeader() []string {
	return []string{
		"Name",
		"UID",
		"HostNetwork",
		"PodIPs",
		"Containers",
		"Phase",
		"Age",
	}
}

func (p LocalPod) TableRow() []string {
	podIPs := make([]string, len(p.Status.PodIPs))
	for i := range p.Status.PodIPs {
		podIPs[i] = p.Status.PodIPs[i].IP
	}
	containers := make([]string, len(p.Spec.Containers))
	for i, cont := range p.Spec.Containers {
		ports := make([]string, len(cont.Ports))
		for i, port := range cont.Ports {
			if port.Name != "" {
				ports[i] = fmt.Sprintf("%d/%s (%s)", port.ContainerPort, string(port.Protocol), port.Name)
			} else {
				ports[i] = fmt.Sprintf("%d/%s", port.ContainerPort, string(port.Protocol))
			}
		}
		contName := cont.Name
		if len(ports) > 0 {
			contName += " (" + strings.Join(ports, ",") + ")"
		}
		containers[i] = contName
	}
	return []string{
		p.Namespace + "/" + p.Name,
		string(p.UID),
		strconv.FormatBool(p.Spec.HostNetwork),
		strings.Join(podIPs, ", "),
		strings.Join(containers, ", "),
		string(p.Status.Phase),
		duration.HumanDuration(time.Since(p.UpdatedAt)),
	}
}

const (
	PodTableName = "k8s-pods"
)

var (
	PodNameIndex = newNameIndex[LocalPod]()
	PodTableCell = cell.Provide(NewPodTableAndReflector)
)

// NewPodTableAndReflector returns the read-only Table[LocalPod] and registers
// the k8s reflector. These are combined to ensure any dependency on Table[LocalPod]
// will start after the reflector, ensuring that Start hooks can wait for the table
// to initialize.
func NewPodTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset) (statedb.Table[LocalPod], error) {
	pods, err := NewPodTable(db)
	if err != nil {
		return nil, err
	}

	if !cs.IsEnabled() {
		return pods, nil
	}

	cfg := podReflectorConfig(cs, pods)
	err = k8s.RegisterReflector(jg, db, cfg)
	return pods, err
}

func PodByName(namespace, name string) statedb.Query[LocalPod] {
	return PodNameIndex.Query(namespace + "/" + name)
}

func NewPodTable(db *statedb.DB) (statedb.RWTable[LocalPod], error) {
	tbl, err := statedb.NewTable(
		PodTableName,
		PodNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

func podReflectorConfig(cs client.Clientset, pods statedb.RWTable[LocalPod]) k8s.ReflectorConfig[LocalPod] {
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.Slim().CoreV1().Pods("")),
		func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + nodeTypes.GetName()).String()
		})
	return k8s.ReflectorConfig[LocalPod]{
		Name:          reflectorName,
		Table:         pods,
		ListerWatcher: lw,
		Transform: func(_ statedb.ReadTxn, obj any) (LocalPod, bool) {
			pod, ok := obj.(*slim_corev1.Pod)
			if !ok {
				return LocalPod{}, false
			}
			return LocalPod{
				Pod:       pod,
				UpdatedAt: time.Now(),
			}, true
		},
	}
}
