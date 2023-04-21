// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package speaker

import (
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	metallbbgp "go.universe.tf/metallb/pkg/bgp"
	metallbspr "go.universe.tf/metallb/pkg/speaker"

	"github.com/cilium/cilium/pkg/cidr"
)

var (
	emptyAdverts = []*metallbbgp.Advertisement{}
)

// CidrSlice is a slice of Cidr strings with a method set for
// converting them to MetalLB advertisements.
type CidrSlice []string

// ToAdvertisements converts the CidrSlice into metallb Advertisements.
//
// If a cidr cannot be parsed it is omitted from the array of Advertisements
// returned an an error is logged.
func (cs CidrSlice) ToAdvertisements() []*metallbbgp.Advertisement {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "CidrSlice.ToAdvertisements",
		})
	)

	adverts := make([]*metallbbgp.Advertisement, 0, len(cs))
	for _, c := range cs {
		parsed, err := cidr.ParseCIDR(c)
		if err != nil {
			continue
		}

		// only advertise ipv4 addresses
		if parsed.IP.To4() == nil {
			// log error and continue
			l.WithField("advertisement", parsed.IP.String()).
				Error("cannot advertise non-v4 prefix")
			continue
		}

		adverts = append(adverts, &metallbbgp.Advertisement{
			Prefix: parsed.IPNet,
		})
	}
	return adverts
}

func (s *MetalLBSpeaker) withdraw() {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "MetalLBSpeaker.withdraw",
		})
	)
	// flip this bool so we start rejecting new events from
	// entering the queue.
	atomic.AddInt32(&s.shutdown, 1)
	var wg sync.WaitGroup // waitgroup here since we don't care about errors
	for _, session := range s.speaker.PeerSessions() {
		wg.Add(1)
		go func(sess metallbspr.Session) { // Need an outer closure to capture session.
			defer wg.Done()
			// providing an empty array of advertisements will
			// provoke the BGP controller to withdrawal any currently
			// advertised bgp routes.
			err := sess.Set(emptyAdverts...)
			if err != nil {
				l.Error("Failed to gracefully remove BGP routes.")
			}
		}(session)
	}
	wg.Wait()
}

// announcePodCidrs will announce the list of cidrs to any
// established BGP sessions.
//
// returning an error from this method will requeue the event
// which triggered the invocation.
//
// This function is not thread safe and should not be called while other functions that modify the underlying speaker
// are being called.
func (s *MetalLBSpeaker) announcePodCIDRs(cidrs CidrSlice) error {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "MetalLBSpeaker.announcePodCidrs",
		})
	)

	ctl := s.speaker.GetBGPController()

	// create advertisements
	adverts := cidrs.ToAdvertisements()
	if len(adverts) == 0 {
		// we logged the error above, but return nil
		// since we don't want to requeue this event.
		return nil
	}
	l.WithField("advertisements", cidrs).
		Info("Advertising CIDRs to all available session")

	ctl.SvcAds["podcidr"] = adverts

	return ctl.UpdateAds()
}
