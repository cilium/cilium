// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/revert"
)

// MigrateENIDatapath migrates the egress rules inside the Linux routing policy
// database (RPDB) for ENI IPAM mode. It will return the number of rules that
// were successfully migrated and the number of rules we've failed to migrated.
// A -1 is returned for the failed number of rules if we couldn't even start
// the migration.
//
// The compat flag will control what Cilium will do in the migration process.
// If the flag is false, this instructs Cilium to ensure the datapath is newer
// (or v2). If the flag is true, Cilium will ensure the original datapath (v1)
// is in-place.
//
// Because this migration is on a best-effort basis, we ensure that each rule
// (or endpoint), at the end, has either the new datapath or the original
// in-place and serviceable. Otherwise we risk breaking connectivity.
//
// We rely on the ability to fetch the CiliumNode resource because we need to
// fetch the number associated with the ENI device. The CiliumNode resource
// contains this information in the Status field. This fetch is abstracted away
// in the (*migrator).getter interface to avoid bringing in K8s logic to this
// low-level datapath code.
//
// This function should be invoked before any endpoints are created.
// Concretely, this function should be invoked before exposing the Cilium API
// and health initialization logic because we want to ensure that no workloads
// are scheduled while this modification is taking place. This migration is
// related to a bug (https://github.com/cilium/cilium/issues/14336) where an
// ENI has an ifindex that equals the main routing table number (253-255),
// causing the rules and routes to be created using the wrong table ID, which
// could end up blackholing most traffic on the node.
func (m *migrator) MigrateENIDatapath(compat bool) (int, int) {
	rules, err := m.rpdb.RuleList(netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).
			Error("Failed to migrate ENI datapath due to a failure in listing the existing rules. " +
				"The original datapath is still in-place, however it is recommended to retry the migration.")
		return 0, -1
	}

	v1Rules := filterRulesByPriority(rules, linux_defaults.RulePriorityEgress)
	v2Rules := filterRulesByPriority(rules, linux_defaults.RulePriorityEgressv2)

	// (1) If compat=false and the current set of rules are under the older
	// priority, then this is an upgrade migration.
	//
	// (2) If compat=false and the current set of rules are under the newer
	// priority, then there is nothing to do.
	//
	// (3) If compat=true and the current set of rules are under the older
	// priority, then there is nothing to do.
	//
	// (4) If compat=true and the current set of rules are under the newer
	// priority, then this is a downgrade migration.

	// Exit if there's nothing to do.
	switch {
	case !compat && len(v1Rules) == 0 && len(v2Rules) > 0: // 2
		fallthrough
	case compat && len(v1Rules) > 0 && len(v2Rules) == 0: // 3
		return 0, 0
	}

	isUpgrade := !compat && len(v1Rules) > 0  // 1
	isDowngrade := compat && len(v2Rules) > 0 // 4

	// The following operation will be done on a per-rule basis (or
	// per-endpoint, assuming that each egress rule has a unique IP addr
	// associated with the endpoint).
	//
	// In both the upgrade and downgrade scenario, the following happens in a
	// specific order to guarantee that any failure at any point won't cause
	// connectivity disruption for the endpoint. Any errors encountered do not
	// stop the migration process because we want to ensure that we conform to
	// either the new state or the old state, and want to avoid being
	// in-between datapath states.
	//   1) Copy over new routes from the old routes
	//   2) Insert new rule
	//   3) Delete old rule
	//   4) Delete old routes
	// Doing (1) & (2) before (3) & (4) allows us to essentially perform an
	// "atomic" swap-in for the new state.
	//
	// (4) is attempted separately outside the main loop because we want to
	// avoid deleting routes for endpoints that share the same table ID. We
	// will delete the routes, if and only if, all endpoints that share the
	// same table ID succeeded in migrating. If an endpoint failed to migrate,
	// then any routes that reference the table ID associated with the
	// endpoint's egress rule will be skipped. This is to prevent disrupting
	// endpoints who relying on the old state to be in-place.
	//
	// If a failure occurs at (1), then the old state can continue to service
	// the endpoint. Similarly with (2) because routes without rules are likely
	// to not have any effect.
	//
	// If a failure occurs at (3), we have already succeeded in getting the new
	// state in-place to direct traffic for the endpoint. In any case of
	// upgrade or downgrade, it is possible for both states to be in-place if
	// there are any failures, especially if there were any failures in
	// reverting. The datapath selected will depend on the rule priority.
	//
	// Concretely, for upgrades, the newer rule will have a lower priority, so
	// the original datapath will be selected. The migration is deemed a
	// failure because the original datapath (with a rule that has a higher
	// priority) is being selected for the endpoint. It is necessary to attempt
	// reverting the failed migration work [(1) & (2)], as leaving the state
	// could block a user's from retrying this upgrade again.
	//
	// For downgrades, the newer rule will have a higher priority, so the newer
	// datapath will be selected. The migration is deemed a success and we
	// explicitly avoid reverting, because it's not necessary to revert this
	// work merely because we failed to cleanup old, ineffectual state.
	//
	// In either case, no connectivity is affected for the endpoint.
	//
	// If we fail at (4), then the old rule will have been deleted and the new
	// state is in-place, which would be servicing the endpoint. The old routes
	// would just be leftover state to be cleaned up at a later point.
	//
	// It is also important to note that we only revert what we've done on a
	// per-rule basis if we fail at (2) or (3). This is by design because we
	// want to ensure that each iteration of the loop is atomic to each
	// endpoint. Meaning, either the endpoint ends up with the new datapath or
	// the original.

	var (
		// Number of rules (endpoints) successfully migrated and how many failed.
		migrated, failed int
		// Store the routes to cleanup in a set after successful migration
		// because routes are only unique per table ID, meaning many endpoints
		// share the same route table if the endpoint's IP is allocated from
		// the same ENI device.
		cleanup = make(map[netlink.Rule][]netlink.Route)
		// Store the table IDs of the routes whose migration failed. This is
		// important because to prevent deleting routes for endpoints that
		// share the same table ID. An example: let's say we have 2 endpoints
		// that have rules and routes that refer to the same table ID. If 1
		// endpoint fails the migration and the other succeeded, we must not
		// remove the routes for the endpoint that failed because it's still
		// relying on them for connectivity.
		failedTableIDs = make(map[int]struct{})
	)

	if isUpgrade {
		for _, r := range v1Rules {
			if routes, err := m.upgradeRule(r); err != nil {
				log.WithError(err).WithField("rule", r).Warn("Failed to migrate endpoint to new ENI datapath. " +
					"Previous datapath is still intact and endpoint connectivity is not affected.")
				failedTableIDs[r.Table] = struct{}{}
				failed++
			} else {
				if rs, found := cleanup[r]; found {
					rs = append(rs, routes...)
					cleanup[r] = rs
				} else {
					cleanup[r] = routes
				}
				migrated++
			}
		}
	} else if isDowngrade {
		for _, r := range v2Rules {
			if routes, err := m.downgradeRule(r); err != nil {
				log.WithError(err).WithField("rule", r).Warn("Failed to downgrade endpoint to original ENI datapath. " +
					"Previous datapath is still intact and endpoint connectivity is not affected.")
				failedTableIDs[r.Table] = struct{}{}
				failed++
			} else {
				if rs, found := cleanup[r]; found {
					rs = append(rs, routes...)
					cleanup[r] = rs
				} else {
					cleanup[r] = routes
				}
				migrated++
			}
		}
	}

	// We store the routes that have already been deleted to de-duplicate and
	// avoid netlink returning "no such process" for a route that has already
	// been deleted. Note the map key is a string representation of a
	// netlink.Route because netlink.Route is not a valid map key because it is
	// incomparable due to containing a slice inside it.
	deleted := make(map[string]struct{}, len(cleanup))

	for rule, routes := range cleanup {
		toDelete := make([]netlink.Route, 0, len(routes))
		for _, ro := range routes {
			if _, skip := failedTableIDs[rule.Table]; skip {
				continue
			}

			if _, already := deleted[ro.String()]; !already {
				// Declare the routes deleted here before the actual deletion
				// below because we don't care if deletion succeeds or not. See
				// comment below on why.
				deleted[ro.String()] = struct{}{}
				toDelete = append(toDelete, ro)
			}
		}

		// This function does not return a revert stack unlike the others
		// because this operation is best-effort. If we fail to delete old
		// routes, then it simply means there is just leftover state left
		// behind, but it has no impact on the datapath whatsoever. We can make
		// that assumption because by the time we call this function, we'd have
		// successfully deleted the old rule which would steer traffic towards
		// these routes.
		//
		// We also don't want to revert here because at this point, the new
		// datapath is in-place and it wouldn't make sense to risk reverting in
		// case of a failure, just to merely cleanup the previous state. We'll
		// live with the leftover state, however the user should be advised to
		// eventually clean this up.
		if err := m.deleteOldRoutes(toDelete); err != nil {
			version := "new"
			if rule.Priority == linux_defaults.RulePriorityEgressv2 {
				version = "original"
			}

			scopedLog := log.WithField("rule", rule)
			scopedLog.WithError(err).WithField("routes", routes).
				Warnf("Failed to cleanup after successfully migrating endpoint to %s ENI datapath. "+
					"It is recommended that theses routes are cleaned up (by running `ip route del`), as it is possible in the future "+
					"to collide with another endpoint with the same IP.", version)
		}
	}

	return migrated, failed
}

// NewMigrator constructs a migrator object with the default implementation to
// use the underlying upstream netlink library to manipulate the Linux RPDB.
// It accepts a getter for retrieving the interface number by MAC address and
// vice versa.
func NewMigrator(getter interfaceDB) *migrator {
	return &migrator{
		rpdb:   defaultRPDB{},
		getter: getter,
	}
}

// upgradeRule migrates the given rule (and endpoint) to the new ENI datapath,
// using the new table ID scheme derived from the ENI interface number. It
// returns the old routes that the caller should remove at a later time, along
// with an error.
func (m *migrator) upgradeRule(rule netlink.Rule) ([]netlink.Route, error) {
	// Let's say we have an ENI device attached to the node with ifindex 3 and
	// interface number 2. The following rule will exist on the node _before_
	// migration.
	//   110:    from 192.168.11.171 to 192.168.0.0/16 lookup 3
	// After the migration, this rule will become:
	//   111:    from 192.168.11.171 to 192.168.0.0/16 lookup 12
	// The priority has been updated to 111 and the table ID is 12 because the
	// interface number is 2 plus the routing table offset
	// (linux_defaults.RouteTableInterfacesOffset). See copyRoutes() for what
	// happens with routes.

	scopedLog := log.WithField("rule", rule)

	routes, err := m.rpdb.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Table: rule.Table,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes associated with rule: %w", err)
	}

	// If there are no routes under the same table as the rule, then
	// skip.
	if len(routes) == 0 {
		scopedLog.Debug("Skipping migration of egress rule due to no routes found")
		return nil, nil
	}

	// It is sufficient to grab the first route that matches because we
	// are assuming all routes created under a rule will have the same
	// ifindex (LinkIndex).
	ifindex := routes[0].LinkIndex
	newTable, err := m.retrieveTableIDFromIfIndex(ifindex)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve new table ID from ifindex %q: %w",
			ifindex, err)
	}

	var (
		stack revert.RevertStack

		oldTable = rule.Table
	)

	revert, err := m.copyRoutes(routes, oldTable, newTable)
	stack.Extend(revert)
	if err != nil {
		return nil, fmt.Errorf("failed to create new routes: %w", err)
	}

	revert, err = m.createNewRule(
		rule,
		linux_defaults.RulePriorityEgressv2,
		newTable,
	)
	stack.Extend(revert)
	if err != nil {
		// We revert here because we want to ensure that the new routes
		// are removed as they'd have no effect, but may conflict with
		// others in the future.
		if revErr := stack.Revert(); revErr != nil {
			scopedLog.WithError(err).WithField("revertError", revErr).Warn(upgradeRevertWarning)
		}

		return nil, fmt.Errorf("failed to create new rule: %w", err)
	}

	if err := m.rpdb.RuleDel(&rule); err != nil {
		// We revert here because we want to ensure that the new state that we
		// just created above is reverted. See long comment describing the
		// migration in MigrateENIDatapath().
		if revErr := stack.Revert(); revErr != nil {
			scopedLog.WithError(err).WithField("revertError", revErr).Warn(upgradeRevertWarning)
		}

		return nil, fmt.Errorf("failed to delete old rule: %w", err)
	}

	return routes, nil
}

// downgradeRule migrates the given rule (and endpoint) to the original ENI
// datapath, using the old table ID scheme that was simply the ifindex of the
// attached ENI device on the node. It returns the "old" routes (new datapath)
// that the caller should remove at a later time, along with an error.
func (m *migrator) downgradeRule(rule netlink.Rule) ([]netlink.Route, error) {
	// Let's say we have an ENI device attached to the node with ifindex 9 and
	// interface number 3. The following rule will exist on the node _before_
	// migration.
	//   111:    from 192.168.11.171 to 192.168.0.0/16 lookup 13
	// After the migration, this rule will become:
	//   110:    from 192.168.11.171 to 192.168.0.0/16 lookup 9
	// The priority has been reverted back to 110 and the table ID back to 9
	// because the ifindex is 9. See copyRoutes() for what happens with routes.

	scopedLog := log.WithField("rule", rule)

	oldTable := rule.Table
	ifaceNumber := oldTable - linux_defaults.RouteTableInterfacesOffset

	newTable, err := m.retrieveTableIDFromInterfaceNumber(ifaceNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve new table ID from interface-number %q: %w",
			ifaceNumber, err)
	}

	routes, err := m.rpdb.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Table: oldTable,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes associated with rule: %w", err)
	}

	var stack revert.RevertStack

	revert, err := m.copyRoutes(routes, oldTable, newTable)
	stack.Extend(revert)
	if err != nil {
		return nil, fmt.Errorf("failed to create new routes: %w", err)
	}

	// We don't need the revert stack return value because the next operation
	// to delete the rule will not revert the stack. See below comment on why.
	_, err = m.createNewRule(
		rule,
		linux_defaults.RulePriorityEgress,
		newTable,
	)
	if err != nil {
		if revErr := stack.Revert(); revErr != nil {
			scopedLog.WithError(err).WithField("revertError", revErr).Warn(downgradeRevertWarning)
		}

		return nil, fmt.Errorf("failed to create new rule: %w", err)
	}

	if err := m.rpdb.RuleDel(&rule); err != nil {
		// We avoid reverting and returning an error here because the newer
		// datapath is already in-place. See long comment describing the
		// migration in MigrateENIDatapath().
		scopedLog.WithError(err).Warn(downgradeFailedRuleDeleteWarning)
		return nil, nil
	}

	return routes, nil
}

const (
	upgradeRevertWarning = "Reverting the new ENI datapath failed. However, the previous datapath is still intact. " +
		"Endpoint connectivity should not be affected. It is advised to retry the migration."
	downgradeRevertWarning = "Reverting the new ENI datapath failed. However, both the new and previous datapaths are still intact. " +
		"Endpoint connectivity should not be affected. It is advised to retry the migration."
	downgradeFailedRuleDeleteWarning = "Downgrading the datapath has succeeded, but failed to cleanup the original datapath. " +
		"It is advised to manually remove the old rule (priority 110)."
)

// retrieveTableIDFromIfIndex computes the correct table ID based on the
// ifindex provided. The table ID is comprised of the number associated with an
// ENI device that corresponds to the ifindex, plus the specific table offset
// value.
func (m *migrator) retrieveTableIDFromIfIndex(ifindex int) (int, error) {
	link, err := m.rpdb.LinkByIndex(ifindex)
	if err != nil {
		return -1, fmt.Errorf("failed to find link by index: %w", err)
	}

	mac := link.Attrs().HardwareAddr.String()
	ifaceNum, err := m.getter.GetInterfaceNumberByMAC(mac)
	if err != nil {
		return -1, fmt.Errorf("failed to get interface-number by MAC %q: %w", mac, err)
	}

	// This is guaranteed to avoid conflicting with the main routing table ID
	// (253-255) because the maximum number of ENI devices on a node is 15 (see
	// pkg/aws/eni/limits.go). Because the interface number is monotonically
	// increasing and the lowest available number is reused when devices are
	// added / removed. This means that the max possible table ID is 25.
	return linux_defaults.RouteTableInterfacesOffset + ifaceNum, nil
}

// retrieveTableIDFromInterfaceNumber returns the table ID based on the
// interface number. The table ID is the ifindex of the device corresponding to
// the ENI with the given interface number. This is used for downgrading /
// using the old ENI datapath.
func (m *migrator) retrieveTableIDFromInterfaceNumber(ifaceNum int) (int, error) {
	mac, err := m.getter.GetMACByInterfaceNumber(ifaceNum)
	if err != nil {
		return -1, fmt.Errorf("failed to get interface-number by MAC %q: %w", mac, err)
	}

	links, err := m.rpdb.LinkList()
	if err != nil {
		return -1, fmt.Errorf("failed to list links: %w", err)
	}

	var (
		link  netlink.Link
		found bool
	)
	for _, l := range links {
		if l.Attrs().HardwareAddr.String() == mac {
			link = l
			found = true
			break
		}
	}

	if !found {
		return -1, fmt.Errorf("could not find link with MAC %q by interface-number %q", mac, ifaceNum)
	}

	return link.Attrs().Index, nil
}

// copyRoutes upserts `routes` under the `from` table ID to `to` table ID. It
// returns a RevertStack and an error. The RevertStack contains functions that
// would revert all the successful operations that occurred in this function.
// The caller of this function MUST revert the stack when this function returns
// an error.
func (m *migrator) copyRoutes(routes []netlink.Route, from, to int) (revert.RevertStack, error) {
	var revertStack revert.RevertStack

	// In ENI mode, we only expect two rules:
	//   1) Link scoped route with a gateway IP
	//   2) Default route via gateway IP
	// We need to add the link-local scope route to the gateway first, then
	// routes that depend on that as a next-hop later. If we didn't do this,
	// then the kernel would complain with "Error: Nexthop has invalid
	// gateway." with an errno of ENETUNREACH.
	for _, r := range routes {
		if r.Scope == netlink.SCOPE_LINK {
			route := r
			route.Table = to
			if err := m.rpdb.RouteReplace(&route); err != nil {
				return revertStack, fmt.Errorf("unable to replace link scoped route under table ID: %w", err)
			}

			revertStack.Push(func() error {
				if err := m.rpdb.RouteDel(&route); err != nil {
					return fmt.Errorf("failed to revert route upsert: %w", err)
				}
				return nil
			})
		}
	}

	for _, r := range routes {
		if r.Scope == netlink.SCOPE_LINK {
			// Skip over these because we already upserted it above.
			continue
		}

		route := r
		route.Table = to
		if err := m.rpdb.RouteReplace(&route); err != nil {
			return revertStack, fmt.Errorf("unable to replace route under table ID: %w", err)
		}

		revertStack.Push(func() error {
			if err := m.rpdb.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to revert route upsert: %w", err)
			}
			return nil
		})
	}

	return revertStack, nil
}

// createNewRule inserts `rule` with the table ID of `newTable` and a priority
// of `toPrio`. It returns a RevertStack and an error. The RevertStack contains
// functions that would revert all the successful operations that occurred in
// this function. The caller of this function MUST revert the stack when this
// function returns an error.
func (m *migrator) createNewRule(rule netlink.Rule, toPrio, newTable int) (revert.RevertStack, error) {
	var revertStack revert.RevertStack

	r := rule
	r.Priority = toPrio
	r.Table = newTable
	if err := m.rpdb.RuleAdd(&r); err != nil {
		return revertStack, fmt.Errorf("unable to add new rule: %w", err)
	}

	revertStack.Push(func() error {
		if err := m.rpdb.RuleDel(&r); err != nil {
			return fmt.Errorf("failed to revert rule insert: %w", err)
		}
		return nil
	})

	return revertStack, nil
}

func (m *migrator) deleteOldRoutes(routes []netlink.Route) error {
	for _, r := range routes {
		if err := m.rpdb.RouteDel(&r); err != nil {
			return fmt.Errorf("unable to delete old route: %w", err)
		}
	}

	return nil
}

func filterRulesByPriority(rules []netlink.Rule, prio int) []netlink.Rule {
	candidates := make([]netlink.Rule, 0, len(rules))
	for _, r := range rules {
		if r.Priority == prio {
			candidates = append(candidates, r)
		}
	}

	return candidates
}

type migrator struct {
	rpdb   rpdb
	getter interfaceDB
}

// defaultRPDB is a simple, default implementation of the rpdb interface which
// forwards all RPDB operations to netlink.
type defaultRPDB struct{}

func (defaultRPDB) RuleList(family int) ([]netlink.Rule, error) { return netlink.RuleList(family) }
func (defaultRPDB) RuleAdd(rule *netlink.Rule) error            { return netlink.RuleAdd(rule) }
func (defaultRPDB) RuleDel(rule *netlink.Rule) error            { return netlink.RuleDel(rule) }
func (defaultRPDB) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, filter, mask)
}
func (defaultRPDB) RouteAdd(route *netlink.Route) error     { return netlink.RouteAdd(route) }
func (defaultRPDB) RouteDel(route *netlink.Route) error     { return netlink.RouteDel(route) }
func (defaultRPDB) RouteReplace(route *netlink.Route) error { return netlink.RouteReplace(route) }
func (defaultRPDB) LinkList() ([]netlink.Link, error)       { return netlink.LinkList() }
func (defaultRPDB) LinkByIndex(ifindex int) (netlink.Link, error) {
	return netlink.LinkByIndex(ifindex)
}

// rpdb abstracts the underlying Linux RPDB operations. This is an interface
// mostly for testing purposes.
type rpdb interface {
	RuleList(int) ([]netlink.Rule, error)
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error

	RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error)
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	RouteReplace(*netlink.Route) error

	LinkList() ([]netlink.Link, error)
	LinkByIndex(int) (netlink.Link, error)
}

type interfaceDB interface {
	GetInterfaceNumberByMAC(mac string) (int, error)
	GetMACByInterfaceNumber(ifaceNum int) (string, error)
}
