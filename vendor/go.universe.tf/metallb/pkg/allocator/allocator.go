package allocator // import "go.universe.tf/metallb/pkg/allocator"

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"

	"go.universe.tf/metallb/pkg/config"

	"github.com/mikioh/ipaddr"
)

// An Allocator tracks IP address pools and allocates addresses from them.
type Allocator struct {
	pools map[string]*config.Pool

	allocated       map[string]*alloc          // svc -> alloc
	sharingKeyForIP map[string]*key            // ip.String() -> assigned sharing key
	portsInUse      map[string]map[Port]string // ip.String() -> Port -> svc
	servicesOnIP    map[string]map[string]bool // ip.String() -> svc -> allocated?
	poolIPsInUse    map[string]map[string]int  // poolName -> ip.String() -> number of users
}

// Port represents one port in use by a service.
type Port struct {
	Proto string
	Port  int
}

// String returns a text description of the port.
func (p Port) String() string {
	return fmt.Sprintf("%s/%d", p.Proto, p.Port)
}

type key struct {
	sharing string
	backend string
}

type alloc struct {
	pool  string
	ip    net.IP
	ports []Port
	key
}

// New returns an Allocator managing no pools.
func New() *Allocator {
	return &Allocator{
		pools: map[string]*config.Pool{},

		allocated:       map[string]*alloc{},
		sharingKeyForIP: map[string]*key{},
		portsInUse:      map[string]map[Port]string{},
		servicesOnIP:    map[string]map[string]bool{},
		poolIPsInUse:    map[string]map[string]int{},
	}
}

// SetPools updates the set of address pools that the allocator owns.
func (a *Allocator) SetPools(pools map[string]*config.Pool) error {
	// All the fancy sharing stuff only influences how new allocations
	// can be created. For changing the underlying configuration, the
	// only question we have to answer is: can we fit all allocated
	// IPs into address pools under the new configuration?
	for svc, alloc := range a.allocated {
		if poolFor(pools, alloc.ip) == "" {
			return fmt.Errorf("new config not compatible with assigned IPs: service %q cannot own %q under new config", svc, alloc.ip)
		}
	}

	for n := range a.pools {
		if pools[n] == nil {
			stats.poolCapacity.DeleteLabelValues(n)
			stats.poolActive.DeleteLabelValues(n)
			stats.poolAllocated.DeleteLabelValues(n)
		}
	}

	a.pools = pools

	// Need to rearrange existing pool mappings and counts
	for svc, alloc := range a.allocated {
		pool := poolFor(a.pools, alloc.ip)
		if pool != alloc.pool {
			a.Unassign(svc)
			alloc.pool = pool
			// Use the internal assign, we know for a fact the IP is
			// still usable.
			a.assign(svc, alloc)
		}
	}

	// Refresh or initiate stats
	for n, p := range a.pools {
		stats.poolCapacity.WithLabelValues(n).Set(float64(poolCount(p)))
		stats.poolActive.WithLabelValues(n).Set(float64(len(a.poolIPsInUse[n])))
	}

	return nil
}

// assign unconditionally updates internal state to reflect svc's
// allocation of alloc. Caller must ensure that this call is safe.
func (a *Allocator) assign(svc string, alloc *alloc) {
	a.Unassign(svc)
	a.allocated[svc] = alloc
	a.sharingKeyForIP[alloc.ip.String()] = &alloc.key
	if a.portsInUse[alloc.ip.String()] == nil {
		a.portsInUse[alloc.ip.String()] = map[Port]string{}
	}
	for _, port := range alloc.ports {
		a.portsInUse[alloc.ip.String()][port] = svc
	}
	if a.servicesOnIP[alloc.ip.String()] == nil {
		a.servicesOnIP[alloc.ip.String()] = map[string]bool{}
	}
	a.servicesOnIP[alloc.ip.String()][svc] = true
	if a.poolIPsInUse[alloc.pool] == nil {
		a.poolIPsInUse[alloc.pool] = map[string]int{}
	}
	a.poolIPsInUse[alloc.pool][alloc.ip.String()]++

	stats.poolCapacity.WithLabelValues(alloc.pool).Set(float64(poolCount(a.pools[alloc.pool])))
	stats.poolActive.WithLabelValues(alloc.pool).Set(float64(len(a.poolIPsInUse[alloc.pool])))
}

// Assign assigns the requested ip to svc, if the assignment is
// permissible by sharingKey and backendKey.
func (a *Allocator) Assign(svc string, ip net.IP, ports []Port, sharingKey, backendKey string) error {
	pool := poolFor(a.pools, ip)
	if pool == "" {
		return fmt.Errorf("%q is not allowed in config", ip)
	}
	sk := &key{
		sharing: sharingKey,
		backend: backendKey,
	}

	// Does the IP already have allocs? If so, needs to be the same
	// sharing key, and have non-overlapping ports. If not, the
	// proposed IP needs to be allowed by configuration.
	if existingSK := a.sharingKeyForIP[ip.String()]; existingSK != nil {
		if err := sharingOK(existingSK, sk); err != nil {
			// Sharing key is incompatible. However, if the owner is
			// the same service, and is the only user of the IP, we
			// can just update its sharing key in place.
			var otherSvcs []string
			for otherSvc := range a.servicesOnIP[ip.String()] {
				if otherSvc != svc {
					otherSvcs = append(otherSvcs, otherSvc)
				}
			}
			if len(otherSvcs) > 0 {
				return fmt.Errorf("can't change sharing key for %q, address also in use by %s", svc, strings.Join(otherSvcs, ","))
			}
		}

		for _, port := range ports {
			if curSvc, ok := a.portsInUse[ip.String()][port]; ok && curSvc != svc {
				return fmt.Errorf("port %s is already in use on %q", port, ip)
			}
		}
	}

	// Either the IP is entirely unused, or the requested use is
	// compatible with existing uses. Assign! But unassign first, in
	// case we're mutating an existing service (see the "already have
	// an allocation" block above). Unassigning is idempotent, so it's
	// unconditionally safe to do.
	alloc := &alloc{
		pool:  pool,
		ip:    ip,
		ports: make([]Port, len(ports)),
		key:   *sk,
	}
	for i, port := range ports {
		port := port
		alloc.ports[i] = port
	}
	a.assign(svc, alloc)
	return nil
}

// Unassign frees the IP associated with service, if any.
func (a *Allocator) Unassign(svc string) bool {
	if a.allocated[svc] == nil {
		return false
	}

	al := a.allocated[svc]
	delete(a.allocated, svc)
	for _, port := range al.ports {
		if curSvc := a.portsInUse[al.ip.String()][port]; curSvc != svc {
			panic(fmt.Sprintf("incoherent state, I thought port %q belonged to service %q, but it seems to belong to %q", port, svc, curSvc))
		}
		delete(a.portsInUse[al.ip.String()], port)
	}
	delete(a.servicesOnIP[al.ip.String()], svc)
	if len(a.portsInUse[al.ip.String()]) == 0 {
		delete(a.portsInUse, al.ip.String())
		delete(a.sharingKeyForIP, al.ip.String())
	}
	a.poolIPsInUse[al.pool][al.ip.String()]--
	if a.poolIPsInUse[al.pool][al.ip.String()] == 0 {
		// Explicitly delete unused IPs from the pool, so that len()
		// is an accurate count of IPs in use.
		delete(a.poolIPsInUse[al.pool], al.ip.String())
	}
	stats.poolActive.WithLabelValues(al.pool).Set(float64(len(a.poolIPsInUse[al.pool])))
	return true
}

func cidrIsIPv6(cidr *net.IPNet) bool {
	return cidr.IP.To4() == nil
}
func ipIsIPv6(ip net.IP) bool {
	return ip.To4() == nil
}

// AllocateFromPool assigns an available IP from pool to service.
func (a *Allocator) AllocateFromPool(svc string, isIPv6 bool, poolName string, ports []Port, sharingKey, backendKey string) (net.IP, error) {
	if alloc := a.allocated[svc]; alloc != nil {
		// Handle the case where the svc has already been assigned an IP but from the wrong family.
		// This "should-not-happen" since the "ipFamily" is an immutable field in services.
		if isIPv6 != ipIsIPv6(alloc.ip) {
			return nil, fmt.Errorf("IP for wrong family assigned %s", alloc.ip.String())
		}
		if err := a.Assign(svc, alloc.ip, ports, sharingKey, backendKey); err != nil {
			return nil, err
		}
		return alloc.ip, nil
	}

	pool := a.pools[poolName]
	if pool == nil {
		return nil, fmt.Errorf("unknown pool %q", poolName)
	}

	for _, cidr := range pool.CIDR {
		if cidrIsIPv6(cidr) != isIPv6 {
			// Not the right ip-family
			continue
		}
		c := ipaddr.NewCursor([]ipaddr.Prefix{*ipaddr.NewPrefix(cidr)})
		for pos := c.First(); pos != nil; pos = c.Next() {
			ip := pos.IP
			if pool.AvoidBuggyIPs && ipConfusesBuggyFirmwares(ip) {
				continue
			}
			// Somewhat inefficiently brute-force by invoking the
			// IP-specific allocator.
			if err := a.Assign(svc, ip, ports, sharingKey, backendKey); err == nil {
				return ip, nil
			}
		}
	}

	// Woops, run out of IPs :( Fail.
	return nil, fmt.Errorf("no available IPs in pool %q", poolName)
}

// Allocate assigns any available and assignable IP to service.
func (a *Allocator) Allocate(svc string, isIPv6 bool, ports []Port, sharingKey, backendKey string) (net.IP, error) {
	if alloc := a.allocated[svc]; alloc != nil {
		if err := a.Assign(svc, alloc.ip, ports, sharingKey, backendKey); err != nil {
			return nil, err
		}
		return alloc.ip, nil
	}

	for poolName := range a.pools {
		if !a.pools[poolName].AutoAssign {
			continue
		}
		if ip, err := a.AllocateFromPool(svc, isIPv6, poolName, ports, sharingKey, backendKey); err == nil {
			return ip, nil
		}
	}

	return nil, errors.New("no available IPs")
}

// IP returns the IP address allocated to service, or nil if none are allocated.
func (a *Allocator) IP(svc string) net.IP {
	if alloc := a.allocated[svc]; alloc != nil {
		return alloc.ip
	}
	return nil
}

// Pool returns the pool from which service's IP was allocated. If
// service has no IP allocated, "" is returned.
func (a *Allocator) Pool(svc string) string {
	ip := a.IP(svc)
	if ip == nil {
		return ""
	}
	return poolFor(a.pools, ip)
}

func sharingOK(existing, new *key) error {
	if existing.sharing == "" {
		return errors.New("existing service does not allow sharing")
	}
	if new.sharing == "" {
		return errors.New("new service does not allow sharing")
	}
	if existing.sharing != new.sharing {
		return fmt.Errorf("sharing key %q does not match existing sharing key %q", new.sharing, existing.sharing)
	}
	if existing.backend != new.backend {
		return fmt.Errorf("backend key %q does not match existing sharing key %q", new.backend, existing.backend)
	}
	return nil
}

// poolCount returns the number of addresses in the pool.
func poolCount(p *config.Pool) int64 {
	var total int64
	for _, cidr := range p.CIDR {
		o, b := cidr.Mask.Size()
		if b-o >= 62 {
			// An enormous ipv6 range is allocated which will never run out.
			// Just return max to avoid any math errors.
			return math.MaxInt64
		}
		sz := int64(math.Pow(2, float64(b-o)))

		cur := ipaddr.NewCursor([]ipaddr.Prefix{*ipaddr.NewPrefix(cidr)})
		firstIP := cur.First().IP
		lastIP := cur.Last().IP

		if p.AvoidBuggyIPs {
			if o <= 24 {
				// A pair of buggy IPs occur for each /24 present in the range.
				buggies := int64(math.Pow(2, float64(24-o))) * 2
				sz -= buggies
			} else {
				// Ranges smaller than /24 contain 1 buggy IP if they
				// start/end on a /24 boundary, otherwise they contain
				// none.
				if ipConfusesBuggyFirmwares(firstIP) {
					sz--
				}
				if ipConfusesBuggyFirmwares(lastIP) {
					sz--
				}
			}
		}
		total += sz
	}
	return total
}

// poolFor returns the pool that owns the requested IP, or "" if none.
func poolFor(pools map[string]*config.Pool, ip net.IP) string {
	for pname, p := range pools {
		if p.AvoidBuggyIPs && ipConfusesBuggyFirmwares(ip) {
			continue
		}
		for _, cidr := range p.CIDR {
			if cidr.Contains(ip) {
				return pname
			}
		}
	}
	return ""
}

func portsEqual(a, b []Port) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ipConfusesBuggyFirmwares returns true if ip is an IPv4 address ending in 0 or 255.
//
// Such addresses can confuse smurf protection on crappy CPE
// firmwares, leading to packet drops.
func ipConfusesBuggyFirmwares(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return ip[3] == 0 || ip[3] == 255
}
