// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"errors"
	"net/netip"
	"regexp"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"

	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/time"
)

var (
	DNSSourceLookup     = "lookup"
	DNSSourceConnection = "connection"
)

type NoEndpointIDMatch struct {
	ID string
}

func (e NoEndpointIDMatch) Error() string {
	return "unable to find target endpoint ID: " + e.ID
}

// model returns the API model of the NameManager.
func (n *manager) model() *models.NameManager {
	n.RWMutex.RLock()
	defer n.RWMutex.RUnlock()

	allSelectors := make([]*models.SelectorEntry, 0, len(n.allSelectors))
	for fqdnSel, regex := range n.allSelectors {
		pair := &models.SelectorEntry{
			SelectorString: fqdnSel.String(),
			RegexString:    regex.String(),
		}
		allSelectors = append(allSelectors, pair)
	}

	return &models.NameManager{
		FQDNPolicySelectors: allSelectors,
	}
}

// dnsHistoryModel returns API models.DNSLookup copies of DNS data in each
// endpoint's DNSHistory. These are filtered by the specified matchers if
// they are non-empty.
//
// Note that this does *NOT* dump the NameManager's own global DNSCache.
//
// endpointID may be "" in order to get DNS history for all endpoints.
func (n *manager) dnsHistoryModel(endpointID string, prefixMatcher fqdn.PrefixMatcherFunc, nameMatcher fqdn.NameMatcherFunc, source string) (lookups []*models.DNSLookup, err error) {
	var eps []*endpoint.Endpoint
	if endpointID == "" {
		eps = n.params.EPMgr.GetEndpoints()
	} else {
		ep, err := n.params.EPMgr.Lookup(endpointID)
		if ep == nil || err != nil {
			return nil, &NoEndpointIDMatch{ID: endpointID}
		}
		eps = append(eps, ep)
	}

	for _, ep := range eps {
		lookupSourceEntries := []*models.DNSLookup{}
		connectionSourceEntries := []*models.DNSLookup{}
		for _, lookup := range ep.DNSHistory.Dump() {
			if !nameMatcher(lookup.Name) {
				continue
			}

			// The API model needs strings
			IPStrings := make([]string, 0, len(lookup.IPs))

			// only proceed if any IP matches the prefix selector
			anIPMatches := false
			for _, ip := range lookup.IPs {
				anIPMatches = anIPMatches || prefixMatcher(ip)
				IPStrings = append(IPStrings, ip.String())
			}
			if !anIPMatches {
				continue
			}

			lookupSourceEntries = append(lookupSourceEntries, &models.DNSLookup{
				Fqdn:           lookup.Name,
				Ips:            IPStrings,
				LookupTime:     strfmt.DateTime(lookup.LookupTime),
				TTL:            int64(lookup.TTL),
				ExpirationTime: strfmt.DateTime(lookup.ExpirationTime),
				EndpointID:     int64(ep.ID),
				Source:         DNSSourceLookup,
			})
		}

		for _, delete := range ep.DNSZombies.DumpAlive(prefixMatcher) {
			for _, name := range delete.Names {
				if !nameMatcher(name) {
					continue
				}

				connectionSourceEntries = append(connectionSourceEntries, &models.DNSLookup{
					Fqdn:           name,
					Ips:            []string{delete.IP.String()},
					LookupTime:     strfmt.DateTime(delete.AliveAt),
					TTL:            0,
					ExpirationTime: strfmt.DateTime(ep.DNSZombies.NextCTGCUpdate()),
					EndpointID:     int64(ep.ID),
					Source:         DNSSourceConnection,
				})
			}
		}

		switch source {
		case DNSSourceLookup:
			lookups = append(lookups, lookupSourceEntries...)
		case DNSSourceConnection:
			lookups = append(lookups, connectionSourceEntries...)
		default:
			lookups = append(lookups, lookupSourceEntries...)
			lookups = append(lookups, connectionSourceEntries...)
		}
	}

	return lookups, nil
}

// deleteDNSLookups force-removes any entries in *all* caches that are not currently actively
// passing traffic.
func (n *manager) deleteDNSLookups(expireLookupsBefore time.Time, matchPatternStr string) error {
	var nameMatcher *regexp.Regexp // nil matches all in our implementation
	if matchPatternStr != "" {
		var err error
		nameMatcher, err = matchpattern.ValidateWithoutCache(matchPatternStr)
		if err != nil {
			return err
		}
	}

	maybeStaleIPs := n.cache.GetIPs()

	// Clear any to-delete entries globally
	// Clear any to-delete entries in each endpoint, then update globally to
	// insert any entries that now should be in the global cache (because they
	// provide an IP at the latest expiration time).
	namesToRegen := n.cache.ForceExpire(expireLookupsBefore, nameMatcher)
	for _, ep := range n.params.EPMgr.GetEndpoints() {
		namesToRegen = namesToRegen.Union(ep.DNSHistory.ForceExpire(expireLookupsBefore, nameMatcher))
		n.cache.UpdateFromCache(ep.DNSHistory, nil)

		namesToRegen.Insert(ep.DNSZombies.ForceExpire(expireLookupsBefore, nameMatcher)...)
		activeConnections := fqdn.NewDNSCache(0)
		zombies, _ := ep.DNSZombies.GC()
		lookupTime := time.Now()
		for _, zombie := range zombies {
			namesToRegen.Insert(zombie.Names...)
			for _, name := range zombie.Names {
				activeConnections.Update(lookupTime, name, []netip.Addr{zombie.IP}, 0)
			}
		}
		n.cache.UpdateFromCache(activeConnections, nil)
	}

	// We may have removed entries; remove them from the ipcache metadata layer
	n.maybeRemoveMetadata(maybeStaleIPs)
	return nil
}

type getFQDNCacheHandler struct {
	*manager
}

func (h *getFQDNCacheHandler) Handle(params GetFqdnCacheParams) middleware.Responder {
	prefixMatcher, nameMatcher, source, err := parseFqdnFilters(params.Cidr, params.Matchpattern, params.Source)
	if err != nil {
		return api.Error(GetFqdnCacheBadRequestCode, err)
	}

	lookups, err := h.dnsHistoryModel("", prefixMatcher, nameMatcher, source)
	switch {
	case err != nil:
		return api.Error(GetFqdnCacheBadRequestCode, err)
	case len(lookups) == 0:
		return NewGetFqdnCacheNotFound()
	}

	return NewGetFqdnCacheOK().WithPayload(lookups)
}

type deleteFQDNCacheHandler struct {
	*manager
}

func (h *deleteFQDNCacheHandler) Handle(params DeleteFqdnCacheParams) middleware.Responder {
	matchPatternStr := ""
	if params.Matchpattern != nil {
		matchPatternStr = *params.Matchpattern
	}

	err := h.deleteDNSLookups(time.Now(), matchPatternStr)
	if err != nil {
		return api.Error(DeleteFqdnCacheBadRequestCode, err)
	}
	return NewDeleteFqdnCacheOK()
}

type getFQDNCacheIDHandler struct {
	*manager
}

func (h *getFQDNCacheIDHandler) Handle(params GetFqdnCacheIDParams) middleware.Responder {
	var epErr NoEndpointIDMatch

	prefixMatcher, nameMatcher, source, err := parseFqdnFilters(params.Cidr, params.Matchpattern, params.Source)
	if err != nil {
		return api.Error(GetFqdnCacheIDBadRequestCode, err)
	}

	lookups, err := h.dnsHistoryModel(params.ID, prefixMatcher, nameMatcher, source)
	switch {
	case errors.As(err, &epErr):
		return api.Error(GetFqdnCacheIDNotFoundCode, err)
	case err != nil:
		return api.Error(GetFqdnCacheIDBadRequestCode, err)
	case len(lookups) == 0:
		return NewGetFqdnCacheIDNotFound()
	}

	return NewGetFqdnCacheIDOK().WithPayload(lookups)
}

type getFQDNNamesHandler struct {
	*manager
}

func (h *getFQDNNamesHandler) Handle(params GetFqdnNamesParams) middleware.Responder {
	payload := h.model()
	return NewGetFqdnNamesOK().WithPayload(payload)
}

func parseFqdnFilters(cidr, pattern, src *string) (fqdn.PrefixMatcherFunc, fqdn.NameMatcherFunc, string, error) {
	prefixMatcher := func(ip netip.Addr) bool { return true }
	if cidr != nil {
		prefix, err := netip.ParsePrefix(*cidr)
		if err != nil {
			return nil, nil, "", err
		}
		prefixMatcher = func(ip netip.Addr) bool { return prefix.Contains(ip) }
	}

	nameMatcher := func(name string) bool { return true }
	if pattern != nil {
		matcher, err := matchpattern.ValidateWithoutCache(matchpattern.Sanitize(*pattern))
		if err != nil {
			return nil, nil, "", err
		}
		nameMatcher = func(name string) bool { return matcher.MatchString(name) }
	}

	source := ""
	if src != nil {
		source = *src
	}

	return prefixMatcher, nameMatcher, source, nil
}
