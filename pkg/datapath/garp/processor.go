// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"context"
	"net/netip"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Processor interface {
	Start(hive.HookContext) error
	Stop(hive.HookContext) error
}

type processorParams struct {
	cell.In

	Logger     logrus.FieldLogger
	Lifecycle  hive.Lifecycle
	Pods       resource.Resource[*corev1.Pod]
	GARPSender Sender
	Config     Config
}

func newGARPProcessor(p processorParams) Processor {
	if !p.Config.EnableL2PodAnnouncements {
		return nil
	}

	if p.Pods == nil {
		return nil
	}

	gp := &processor{
		log:         p.Logger,
		pods:        p.Pods,
		garpSender:  p.GARPSender,
		podIPsState: make(map[resource.Key]netip.Addr),
	}

	p.Lifecycle.Append(gp)

	p.Logger.Info("initialised gratuitous arp processor")

	return gp
}

type processor struct {
	wp *workerpool.WorkerPool

	log        logrus.FieldLogger
	pods       resource.Resource[*corev1.Pod]
	garpSender Sender

	podIPsState map[resource.Key]netip.Addr
}

func (gp *processor) Start(hive.HookContext) error {
	gp.wp = workerpool.New(1)
	gp.wp.Submit("GARPProcessorLoop", gp.run)
	return nil
}

func (gp *processor) Stop(hive.HookContext) error {
	gp.wp.Close()
	return nil
}

func (gp *processor) run(ctx context.Context) error {
	pods := gp.pods.Events(ctx)

	for pods != nil {
		event, ok := <-pods
		if !ok {
			pods = nil
			continue
		}

		if event.Kind == resource.Upsert {
			if err := gp.upsert(&event); err != nil {
				event.Done(err)
				continue
			}
		}

		if event.Kind == resource.Delete {
			delete(gp.podIPsState, event.Key)
		}

		event.Done(nil)
	}

	return nil
}

func (gp *processor) upsert(event *resource.Event[*corev1.Pod]) error {
	if event.Object.Status.PodIPs == nil {
		return nil
	}

	newIP := getPodIPv4(event.Object.Status.PodIPs)
	if !newIP.IsValid() {
		return nil
	}

	oldIP, ok := gp.podIPsState[event.Key]
	if ok && oldIP == newIP {
		return nil
	}

	gp.podIPsState[event.Key] = newIP

	if err := gp.garpSender.Send(newIP); err != nil {
		return err
	}

	gp.log.WithFields(logrus.Fields{
		logfields.K8sPodName: event.Key.Name,
		logfields.IPAddr:     newIP,
	}).Debug("pod upsert gratuitous arp sent")

	return nil
}

// getPodIPv4 returns the IPv4 address from the given Pod IPs, if
// available.
func getPodIPv4(podIPs []corev1.PodIP) netip.Addr {
	for _, podIP := range podIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			continue
		}

		ip = ip.Unmap()
		if ip.Is4() {
			// Valid v4 address found, return it.
			return ip
		}
	}

	// No valid v4 address found, return the zero value.
	return netip.Addr{}
}
