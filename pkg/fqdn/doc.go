// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package fqdn handles some of the DNS-based policy functions:
//   - A DNS lookup cache used to populate toFQDNs rules in the policy layer.
//   - A NameManager that coordinates distributing IPs to matching toFQDNs
//     selectors.
//   - A DNS Proxy that applies L7 DNS rules and populates the lookup cache with
//     IPs from allowed/successful DNS lookups.
//   - (deprecated) A DNS Poller that actively polls all L3 toFQDNs.MatchName
//     entries and populates the DNS lookup cache.
//
// Note: There are 2 different requests that are handled: the DNS lookup and
// the connection to the domain in the DNS lookup.
//
// Proxy redirection and L3 policy calculations are handled by the datapath and
// policy layer, respectively.
//
// DNS data is tracked per-endpoint but collected globally in each cilium-agent
// when calculating policy. This differs from toEndpoints rules, which use
// cluster-global information, and toCIDR rules, which use static information
// in the policy. toServices rules are similar but they are cluster-global and
// have no TTL nor a distinct lookup request from the endpoint. Furthermore,
// toFQDNs cannot handle in-cluster IPs but toServices can.
//
//	+-------------+   +----------------+        +---------+     +---------+
//	|             |   |                |        |         |     |         |
//	|             +<--+   NameManager  +<-------+         |     |         |
//	|             |   |                | Update |         |     |         |
//	|   Policy    |   +-------+--------+ Trigger|   DNS   |     |         |
//	|  Selectors  |           ^                 |  Proxy  +<--->+ Network |
//	|             |           |                 |         |     |         |
//	|             |   +-------+--------+        |         |     |         |
//	|             |   |      DNS       |        |         |     |         |
//	|             |   |  Lookup Cache  +<-------+         |     |         |
//	+------+------+   |                |   DNS  +----+----+     +----+----+
//	       |          +----------------+   Data      ^               ^
//	       v                                         |               |
//	+------+------+--------------------+             |               |
//	|             |                    |             |               |
//	|   Datapath  |                    |             |               |
//	|             |                    |   DNS Lookup|               |
//	+-------------+                    +<------------+               |
//	|                                  |                             |
//	|                Pod               |                             |
//	|                                  |                   HTTP etc. |
//	|                                  +<----------------------------+
//	|                                  |
//	+----------------------------------+
//
// === L7 DNS ===
// L7 DNS is handled by the DNS Proxy. The proxy is always running within
// cilium-agent but traffic is only redirected to it when a L7 rule includes a
// DNS section such as:
//
//	---
//	- toEndpoints:
//	  toPorts:
//	  - ports:
//	     - port: "53"
//	       protocol: ANY
//	    rules:
//	      dns:
//	        - matchPattern: "*"
//	        - matchName: "cilium.io"
//
// These redirects are implemented by the datapath and the management logic is
// shared with other proxies in cilium (envoy and kafka). L7 DNS rules can
// apply to an endpoint from various policies and, if any allow a request, it
// will be forwarded to the original target of the DNS packet. This is often
// configured in /etc/resolv.conf for a pod and k8s sets this automatically
// (https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-config)
// In the example above `matchPattern: "*"` allows all requests and makes
// `matchName: "cilium.io"` redundant.
// Notes:
//   - The forwarded requests are sent from cilium-agent on the host interface
//     and not from the endpoint.
//   - Users must explicitly allow `*.*.svc.cluster.local.` in k8s clusters.
//     This is not automatic.
//   - L7 DNS rules are egress-only,
//   - The proxy emits L7 cilium-monitor events: one for the request, an
//     accept/reject event, and the final response.
//
// Apart from allowing or denying DNS requests, the DNS proxy is used to
// observe DNS lookups in order to then allow L3 connections with the response
// information. These must separately allowed with toFQDNs L3 rules. The
// example above is a common "visibility" policy that allows all requests but
// ensures that they traverse the proxy. This information is then placed in the
// per-Endpoint and global DNS lookup caches and propagates from there.
//
// === L3 DNS ===
// L3 DNS rules control L3 connections and not the DNS requests themselves.
// They rely on DNS lookup cache information and it must come from the DNS
// proxy, or via a L7 DNS rule.
//
//	---
//	- toFQDNs:
//	    - matchName: "my-remote-service.com"
//	    - matchPattern: "bucket.*.my-remote-service.com"
//
// IPs seen in a DNS response (i.e. the request was allowed by a L7 policy)
// that are also selected in a DNS L3 rule matchPattern or matchName have a /32
// or /128 CIDR identity created. This occurs when they are first passed to the
// toFQDN selectors from NameManager. These identities are not special in any
// way and can overlap with toCIDR rules in policiies. They are placed in the
// node-local ipcache and in the policy map of each endpoint that is allowed to
// connect to them (i.e. defined in the L3 DNS rule).
// Notes:
//   - Generally speaking, toFQDNs can only handle non-cluster IPs. In-cluster
//     policy should use toEndpoints and toServices. This is partly historical but
//     is because of ipcache limitations when mapping ip->identity. Endpoint
//     identities can clobber the FQDN IP identity.
//   - Despite being tracked per-Endpoint. DNS lookup IPs are collected into a
//     global cache. This is historical and can be changed.
//     The original implementation created policy documents in the policy
//     repository to represent the IPs being allowed and could not distinguish
//     between endpoints. The current implementation uses selectors that also do
//     not distinguish between Endpoints. There is some provision for this,
//     however, and it just requires better plumbing in how we place data in the
//     Endpoint's datapath.
//
// === Caching, Long-Lived Connections & Garbage Collection ===
// DNS requests are distinct traffic from the connections that pods make with
// the response information. This makes it difficult to correlate one DNS
// lookup to a later connection; a pod may reuse the IPs in a DNS response an
// arbitrary time after the lookup occurred, even past the DNS TTL. The
// solution is multi-layered for historical reasons:
//   - Keep a per-Endpoint cache that can be stored to disk and restored on
//     startup. These caches apply TTL expiration and limit the IP count per domain.
//   - Keep a global cache to combine all this DNS information and send it to the
//     policy system. This cache applies TTL but not per-domain limits.
//     This causes a DNS lookup in one endpoint to leak to another!
//   - Track live connections allowed by DNS policy and delay expiring that data
//     while the connection is open. If the policy itself is removed, however, the
//     connection is interrupted.
//
// The same DNSCache type is used in all cases. DNSCache instances remain
// consistent if the update order is different and merging multiple caches
// should be equivalent to applying the constituent updates individually. As a
// result, DNS data is all inserted into a single global cache from which the
// policy layer receives information. This is historic and per-Endpoint
// handling can be added. The data is internally tracked per IP because
// overlapping DNS responses may have different TTLs for IPs that appear in
// both.
// Notes:
//   - The default configurable minimum TTL in the caches is 1 hour. This is
//     mostly for identity stability, as short TTLs would cause more identity
//     churn. This is mostly history as CIDR identities now have a near-0
//     allocation overhead.
//   - DNSCache deletes only currently occur when the cilium API clears the cache
//     or when the garbage collector evicts entries.
//   - The combination of caches: per-Endpoint and global must manage disparate
//     behaviours of pods. The worst case scenario is one where one pod makes many
//     requests to a target with changing IPs (like S3) but another makes few
//     requests that are long-lived. We need to ensure "fairness" where one does
//     not starve the other. The limits in the per-Endpoint caches allow this, and
//     the global cache acts as a collector across different Endpoints (without
//     restrictions).
//
// Expiration of DNS data is handled by the dns-garbage-collector-job controller.
// Historically, the only expiration was TTL based and the per-Endpoint and
// global caches would expire data at the same time without added logic.
// This is not true when we apply per-host IP limits in the cache. These
// default to 50 IPs for a given domain, per Endpoint. To account for these
// evictions the controller handles TTL and IP limit evictions. This ensures
// that the global cache is consistent with the per-Endpoint caches. The result
// is that the actual expiration is imprecise (TTL especially). The caches mark
// to-evict data internally and only do so on GC method calls from the
// controller.
// When DNS data is evicted from any per-Endpoint cache, for any reason, each
// IP is retained as a "zombie" in type fqdn.DNSZombieMapping. These "zombies"
// represent IPs that were previously associated with a resolved DNS name, but
// the DNS name is no longer known (for example because of TTL expiry). However
// there may still be an active connection associated with the zombie IP.
// Externally, related options use the term "deferred connection delete".
// Zombies are tracked per IP for the endpoint they come from (with a default
// limit of 10000 set by defaults.ToFQDNsMaxDeferredConnectionDeletes). When
// the Connection Tracking garbage collector runs, it marks any zombie IP that
// correlates to a live connection by that endpoint as "alive". At the next
// iteration of the dns-garbage-collector-job controller, the not-live zombies
// are finally evicted. These IPs are then, finally, no longer placed into the
// global cache on behalf of this endpoint. Other endpoints may have live DNS
// TTLs or connections to the same IPs, however, so these IPs may be inserted
// into the global cache for the same domain or a different one (or both).
// Note: The CT GC has a variable run period. This ranges from 30s to 12 hours
// and is shorter when more connection churn is observed (the constants are
// ConntrackGCMinInterval and ConntrackGCMaxLRUInterval in package defaults).
//
// === Flow of DNS data ===
//
//	+---------------------+
//	|      DNS Proxy      |
//	+----------+----------+
//	           |
//	           v
//	+----------+----------+
//	| per-EP Lookup Cache |
//	+----------+----------+
//	           |
//	           v
//	+----------+----------+
//	| per-EP Zombie Cache |
//	+----------+----------+
//	           |
//	           v
//	+----------+----------+
//	|  Global DNS Cache   |
//	+----------+----------+
//	           |
//	           v
//	+----------+----------+
//	|     NameManager     |
//	+----------+----------+
//	           |
//	           v
//	+----------+----------+
//	|   Policy toFQDNs    |
//	|      Selectors      |
//	+----------+----------+
//	           |
//	           v
//	+----------+----------+
//	|   per-EP Datapath   |
//	+---------------------+
package fqdn
