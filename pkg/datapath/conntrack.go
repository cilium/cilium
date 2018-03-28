// Copyright 2016-2017 Authors of Cilium
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

package datapath

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/status"

	"github.com/sirupsen/logrus"
)

// EndpointManager is the interface the owner of endpoints must implement
type EndpointManager interface {
	// GetDatapathEndpoints must return a slice of all datapath relevant
	// endpoints
	GetDatapathEndpoints() []Endpoint

	// IPv4Enabled must return true if IPv4 is enabled
	IPv4Enabled() bool

	// IPv6Enabled must return true if IPv4 is enabled
	IPv6Enabled() bool
}

// Endpoint are the requirements of an requiring datapath plumbing
type Endpoint interface {
	// GetID must return the identifier of the endpoin
	GetID() uint64

	// LogStatus must log a status entry
	LogStatus(typ status.Type, code status.Code, msg string)

	// UseIsolatedConntrack must return true if the endpoint is configured
	// to use an isolated connection tracking table
	UseIsolatedConntrack() bool
}

// runGC run CT's garbage collector for the given endpoint. `isLocal` refers if
// the CT map is set to local. If `isIPv6` is set specifies that is the IPv6
// map. `filter` represents the filter type to be used while looping all CT
// entries.
func runGC(e Endpoint, isLocal, isIPv6 bool, filter *ctmap.GCFilter) {
	var file string
	var mapType string
	// TODO: We need to optimize this a bit in future, so we traverse
	// the global table less often.

	// Use local or global conntrack maps depending on configuration settings.
	if isLocal {
		if isIPv6 {
			mapType = ctmap.MapName6
		} else {
			mapType = ctmap.MapName4
		}
		file = bpf.MapPath(mapType + strconv.Itoa(int(e.GetID())))
	} else {
		if isIPv6 {
			mapType = ctmap.MapName6Global
		} else {
			mapType = ctmap.MapName4Global
		}
		file = bpf.MapPath(mapType)
	}

	m, err := bpf.OpenMap(file)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, file).Warn("Unable to open map")
		e.LogStatus(status.BPF, status.Warning, fmt.Sprintf("Unable to open CT map %s: %s", file, err))
		return
	}
	defer m.Close()

	deleted := ctmap.GC(m, mapType, filter)

	if deleted > 0 {
		log.WithFields(logrus.Fields{
			logfields.Path:  file,
			"ctFilter.type": filter.TypeString(),
			"count":         deleted,
		}).Debug("Deleted filtered entries from map")
	}
}

// runConntrackGC performs a conntrack gc cycle on all endpoints
func runConntrackGC() {
	seenGlobal := false
	sleepTime := time.Duration(GcInterval) * time.Second
	for {
		eps := manager.GetDatapathEndpoints()
		for _, e := range eps {
			// Only process global CT once per round.  We don't
			// really care about which EP triggers the traversal as
			// long as we do traverse it eventually. Update/delete
			// combo only serialized done from here, so no extra
			// mutex for global CT needed right now. We still need
			// to traverse other EPs since some may not be part of
			// the global CT, but have a local one.
			isLocal := e.UseIsolatedConntrack()
			if isLocal == false {
				if seenGlobal == true {
					continue
				}
				seenGlobal = true
			}

			if manager.IPv6Enabled() {
				runGC(e, isLocal, true, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
			}
			if manager.IPv4Enabled() {
				runGC(e, isLocal, false, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
			}
		}

		time.Sleep(sleepTime)
		seenGlobal = false
	}
}

// ResetProxyPort modifies the connection tracking table of the given endpoint
// `e`. It modifies all CT entries that of the CT table local or global, defined
// by isLocal, that contain:
//  - all the endpoint IP addresses given in the epIPs slice AND
//  - any of the given ids in the idsMod map, maps to true and matches the
//    src_sec_id in the CT table.
func ResetProxyPort(e Endpoint, isLocal bool, epIPs []net.IP, idsMod policy.SecurityIDContexts) {

	gcFilter := ctmap.NewGCFilterBy(ctmap.GCFilterByIDToMod)
	gcFilter.IDsToMod = idsMod
	gcFilter.EndpointID = uint16(e.GetID())
	for _, epIP := range epIPs {
		gcFilter.EndpointIP = epIP

		if epIP.To4() == nil {
			runGC(e, isLocal, true, gcFilter)
		} else if manager.IPv4Enabled() {
			runGC(e, isLocal, false, gcFilter)
		}
	}
}

// FlushCTEntries cleans the connection tracking table of the given endpoint
// `e`. It removes all CT entries that of the CT table local or global, defined
// by isLocal, that contains:
//  - all the endpoint IP addresses given in the epIPs slice AND
//  - does not belong to the list of ids to keep
func FlushCTEntries(e Endpoint, isLocal bool, epIPs []net.IP, idsToKeep policy.SecurityIDContexts) {

	gcFilter := ctmap.NewGCFilterBy(ctmap.GCFilterByIDsToKeep)
	gcFilter.IDsToKeep = idsToKeep
	gcFilter.EndpointID = uint16(e.GetID())
	for _, epIP := range epIPs {
		gcFilter.EndpointIP = epIP

		if epIP.To4() == nil {
			runGC(e, isLocal, true, gcFilter)
		} else if manager.IPv4Enabled() {
			runGC(e, isLocal, false, gcFilter)
		}
	}
}
