// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	// L2PodAnnouncementsInterface is the interface used to send Gratuitous ARP messages.
	L2PodAnnouncementsInterface = "l2-pod-announcements-interface"

	EnableL2PodAnnouncements = "enable-l2-pod-announcements"
)

// Config contains the configuration for the GARP cell.
type Config struct {
	L2PodAnnouncementsInterface string
	EnableL2PodAnnouncements    bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(L2PodAnnouncementsInterface, def.L2PodAnnouncementsInterface, "Interface used for sending gratuitous arp messages")
	flags.Bool(EnableL2PodAnnouncements, def.EnableL2PodAnnouncements, "Enable announcing Pod IPs with Gratuitous ARP")
}

var localPodsCell = cell.ProvidePrivate(func(lc hive.Lifecycle, c k8sClient.Clientset) (resource.Resource[*corev1.Pod], error) {
	if !c.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithFields(utils.ListerWatcherFromTyped[*corev1.PodList](
		c.CoreV1().Pods("")), fields.OneTermEqualSelector("spec.nodeName", nodeTypes.GetName()),
	)
	return resource.New[*corev1.Pod](lc, lw), nil
})

// Cell processes k8s pod events for the local node and determines if a
// Gratuitous ARP packet needs to be sent.
var Cell = cell.Module(
	"l2-pod-announcements-garp",
	"GARP processor sends gratuitous ARP packets for local pods",

	localPodsCell,
	cell.Provide(newGARPSender),

	// This cell can't have a default config, it's entirely env dependent.
	cell.Config(Config{}),

	cell.Invoke(newGARPProcessor),
)
