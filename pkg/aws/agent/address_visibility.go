// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

const (
	addressVisibilityPollInterval = time.Second
	addressVisibilityTimeout      = 5 * time.Minute
	addressVisibilityIMDSTimeout  = 5 * time.Second
)

type listInterfaceAddressesFunc func(ctx context.Context, mac string) (awsMetadata.InterfaceAddresses, error)

// eniRef identifies the ENI an address or prefix belongs to.
type eniRef struct {
	id  string
	mac mac.MAC
}

type visibilityEntry struct {
	eniRef
	firstSeen time.Time
	// pending stays true until the IMDS lists the entry or the entry expires.
	pending bool
}

// addressVisibility logs how long the IMDS takes to list each ENI address of the CiliumNode.
type addressVisibility struct {
	logger *slog.Logger
	list   listInterfaceAddressesFunc
	now    func() time.Time

	mu lock.Mutex
	// synced turns true at the first Sync event, and only entries seen after it are timed.
	synced bool
	// entries holds secondary addresses as host prefixes and delegated prefixes as /28s.
	entries map[netip.Prefix]*visibilityEntry
}

func newAddressVisibility(logger *slog.Logger, list listInterfaceAddressesFunc) *addressVisibility {
	return &addressVisibility{
		logger:  logger,
		list:    list,
		now:     time.Now,
		entries: map[netip.Prefix]*visibilityEntry{},
	}
}

// startAddressVisibility registers the jobs that time the local ENI addresses against the IMDS, if debug logging is on.
func startAddressVisibility(
	logger *slog.Logger,
	jg job.Group,
	nodeResource agentK8s.LocalCiliumNodeResource,
	list listInterfaceAddressesFunc,
) *addressVisibility {
	if !logger.Enabled(context.Background(), slog.LevelDebug) {
		return nil
	}
	v := newAddressVisibility(logger, list)
	jg.Add(
		job.Observer(
			"eni-address-visibility",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				switch ev.Kind {
				case resource.Sync:
					v.sync()
				case resource.Upsert:
					v.observe(ev.Object)
				case resource.Delete:
					v.observe(nil)
				}
				return nil
			},
			nodeResource,
		),
		job.OneShot("eni-address-visibility-poll", v.run),
	)
	return v
}

// statusIPv4Entries returns the IPv4 addresses and prefixes that poolAccessor offers.
func statusIPv4Entries(node *ciliumv2.CiliumNode) map[netip.Prefix]eniRef {
	entries := map[netip.Prefix]eniRef{}
	if node == nil {
		return entries
	}

	for _, eni := range node.Status.ENI.ENIs {
		if eni.IsExcludedBySpec(node.Spec.ENI) || !eni.MAC.IsValid() {
			continue
		}
		ref := eniRef{id: eni.ID, mac: eni.MAC}

		var prefixes []netip.Prefix
		for _, p := range eni.Prefixes {
			if !p.IsValid() || !p.Addr().Is4() {
				continue
			}
			prefixes = append(prefixes, p.Prefix)
			entries[p.Masked()] = ref
		}

		for _, addr := range eni.Addresses {
			if !addr.IsValid() || !addr.Is4() || addressCoveredByPrefix(addr.Addr, prefixes) {
				continue
			}
			entries[netip.PrefixFrom(addr.Addr, addr.BitLen())] = ref
		}
	}
	return entries
}

// observe tracks the entries new in node and forgets those that left it or moved to another ENI.
func (v *addressVisibility) observe(node *ciliumv2.CiliumNode) {
	current := statusIPv4Entries(node)
	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()

	for p, e := range v.entries {
		if ref, ok := current[p]; !ok || ref != e.eniRef {
			delete(v.entries, p)
		}
	}

	for p, ref := range current {
		if _, ok := v.entries[p]; !ok {
			v.entries[p] = &visibilityEntry{eniRef: ref, firstSeen: now, pending: v.synced}
		}
	}
}

// sync marks the end of the initial listing, whose entries IMDS may have listed long ago.
func (v *addressVisibility) sync() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.synced = true
}

// run polls the IMDS every addressVisibilityPollInterval.
func (v *addressVisibility) run(ctx context.Context, _ cell.Health) error {
	ticker := time.NewTicker(addressVisibilityPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			v.poll(ctx)
		}
	}
}

// poll queries the IMDS once per ENI with pending entries.
func (v *addressVisibility) poll(ctx context.Context) {
	for _, m := range v.pendingMACs() {
		listCtx, cancel := context.WithTimeout(ctx, addressVisibilityIMDSTimeout)
		listed, err := v.list(listCtx, m.String())
		cancel()
		if err != nil {
			v.logger.Debug("Unable to list ENI addresses in instance metadata",
				logfields.MACAddr, m,
				logfields.Error, err,
			)
			continue
		}
		v.markListed(m, listed)
	}
}

// pendingMACs expires the entries past addressVisibilityTimeout and returns the pending MACs.
func (v *addressVisibility) pendingMACs() []mac.MAC {
	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()

	seen := map[mac.MAC]struct{}{}
	var macs []mac.MAC
	for p, e := range v.entries {
		if !e.pending {
			continue
		}
		if age := now.Sub(e.firstSeen); age >= addressVisibilityTimeout {
			e.pending = false
			v.logger.Debug("ENI address not listed in instance metadata, no longer tracking it",
				logfields.CIDR, p,
				logfields.ENI, e.id,
				logfields.MACAddr, e.mac,
				logfields.Duration, age,
			)
			continue
		}
		if _, ok := seen[e.mac]; !ok {
			seen[e.mac] = struct{}{}
			macs = append(macs, e.mac)
		}
	}
	return macs
}

// markListed stops tracking the entries of the ENI with MAC m that the IMDS lists.
func (v *addressVisibility) markListed(m mac.MAC, listed awsMetadata.InterfaceAddresses) {
	set := make(map[netip.Prefix]struct{}, len(listed.IPv4s)+len(listed.IPv4Prefixes))
	for _, addr := range listed.IPv4s {
		set[netip.PrefixFrom(addr, addr.BitLen())] = struct{}{}
	}
	for _, p := range listed.IPv4Prefixes {
		set[p.Masked()] = struct{}{}
	}

	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()

	for p, e := range v.entries {
		if !e.pending || e.mac != m {
			continue
		}
		if _, ok := set[p]; !ok {
			continue
		}
		e.pending = false
		v.logger.Debug("ENI address listed in instance metadata",
			logfields.CIDR, p,
			logfields.ENI, e.id,
			logfields.MACAddr, e.mac,
			logfields.Duration, now.Sub(e.firstSeen),
		)
	}
}

// allocating logs the allocation of addr while the IMDS does not list it yet.
func (v *addressVisibility) allocating(addr netip.Addr) {
	if v == nil || !addr.Is4() {
		return
	}
	now := v.now()

	v.mu.Lock()
	defer v.mu.Unlock()

	for p, e := range v.entries {
		if !e.pending || !p.Contains(addr) {
			continue
		}
		v.logger.Debug("Allocating ENI address before instance metadata lists it",
			logfields.IPAddr, addr,
			logfields.CIDR, p,
			logfields.ENI, e.id,
			logfields.MACAddr, e.mac,
			logfields.Duration, now.Sub(e.firstSeen),
		)
		return
	}
}
