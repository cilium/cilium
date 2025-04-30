// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maglev

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"iter"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/murmur3"
)

var Cell = cell.Module(
	"maglev",
	"Maglev table computations",

	cell.Config(DefaultUserConfig),
	cell.Provide(
		New,
		UserConfig.ToConfig,
	),
)

const (
	DefaultTableSize = 16381

	// seed=$(head -c12 /dev/urandom | base64 -w0)
	DefaultHashSeed = "JLfvgnHc2kaSUFaI"

	MaglevTableSizeName = "bpf-lb-maglev-table-size"
	MaglevHashSeedName  = "bpf-lb-maglev-hash-seed"
)

var (
	maglevSupportedTableSizes = []uint{251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071}
)

// UserConfig is the user-facing configuration, i.e. the command-line flags.
type UserConfig struct {
	// Maglev backend table size (M) per service. Must be prime number.
	// "Let N be the size of a VIP's backend pool." [...] "In practice, we choose M to be
	// larger than 100 x N to ensure at most a 1% difference in hash space assigned to
	// backends." (from Maglev paper, page 6)
	TableSize uint `mapstructure:"bpf-lb-maglev-table-size"`

	// HashSeed contains the cluster-wide seed for the hash(es).
	HashSeed string `mapstructure:"bpf-lb-maglev-hash-seed"`
}

func (def UserConfig) Flags(flags *pflag.FlagSet) {
	flags.Uint(MaglevTableSizeName, def.TableSize, fmt.Sprintf("Maglev per service backend table size (parameter M, one of: %v)", maglevSupportedTableSizes))
	flags.String(MaglevHashSeedName, def.HashSeed, "Maglev cluster-wide hash seed (base64 encoded)")
}

func (userCfg UserConfig) ToConfig() (Config, error) {
	if !slices.Contains(maglevSupportedTableSizes, userCfg.TableSize) {
		return Config{}, fmt.Errorf("Invalid value for --%s: %d, supported values are: %v",
			MaglevTableSizeName, userCfg.TableSize, maglevSupportedTableSizes)
	}

	seed := userCfg.HashSeed
	d, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return Config{}, fmt.Errorf("cannot decode base64 Maglev hash seed %q: %w", seed, err)
	}
	if len(d) != 12 {
		return Config{}, fmt.Errorf("decoded hash seed is %d bytes (not 12 bytes)", len(d))
	}
	return Config{
		TableSize:  userCfg.TableSize,
		HashSeed:   userCfg.HashSeed,
		SeedMurmur: uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3]),
		SeedJhash0: uint32(d[4])<<24 | uint32(d[5])<<16 | uint32(d[6])<<8 | uint32(d[7]),
		SeedJhash1: uint32(d[8])<<24 | uint32(d[9])<<16 | uint32(d[10])<<8 | uint32(d[11]),
	}, nil
}

var DefaultUserConfig = UserConfig{
	TableSize: DefaultTableSize,
	HashSeed:  DefaultHashSeed,
}

// DefaultConfig is the default maglev configuration for testing.
var DefaultConfig, _ = DefaultUserConfig.ToConfig()

// Config is the maglev configuration derived from the user configuration.
type Config struct {
	// Maglev backend table size (M) per service. Must be prime number.
	// "Let N be the size of a VIP's backend pool." [...] "In practice, we choose M to be
	// larger than 100 x N to ensure at most a 1% difference in hash space assigned to
	// backends." (from Maglev paper, page 6)
	TableSize uint

	// HashSeed contains the cluster-wide seed for the hash(es).
	HashSeed string

	SeedJhash0 uint32
	SeedJhash1 uint32
	SeedMurmur uint32
}

type Maglev struct {
	Config

	// mu protects the fields below
	mu lock.Mutex

	wp *workerpool.WorkerPool

	// backendInfosBuffer is a reusable buffer for holding the backend infos.
	backendInfosBuffer []BackendInfo

	// permutations is (re)used during each GetLookupTable call to compute the table.
	permutations []uint64
}

// New constructs a new Maglev computation object.
func New(cfg Config, lc cell.Lifecycle) *Maglev {
	ml := &Maglev{
		Config: cfg,
	}
	lc.Append(ml)
	return ml
}

func (ml *Maglev) Start(cell.HookContext) error {
	ml.wp = workerpool.New(runtime.NumCPU())
	return nil
}

func (ml *Maglev) Stop(cell.HookContext) error {
	err := ml.wp.Close()
	*ml = Maglev{}
	return err
}

func (ml *Maglev) getPermutation(backends []BackendInfo, numCPU int) []uint64 {
	if len(backends) == 0 {
		return nil
	}

	m := int(ml.TableSize)

	if size := len(backends) * int(m); size > len(ml.permutations) {
		// As the permutations array is large and often used, we'll keep a single
		// instance around and reuse it.
		minSize := derivePermutationSliceLen(uint64(ml.Config.TableSize))
		ml.permutations = make([]uint64, max(minSize, size))
	}

	// The idea is to split the calculation into batches so that they can be
	// concurrently executed. We limit the number of concurrent goroutines to
	// the number of available CPU cores. This is because the calculation does
	// not block and is completely CPU-bound. Therefore, adding more goroutines
	// would result into an overhead (allocation of stackframes, stress on
	// scheduling, etc) instead of a performance gain.
	bCount := len(backends)

	batchSize := bCount / numCPU
	if batchSize == 0 {
		batchSize = bCount
	}

	// Since no other goroutine is controlling the WorkerPool, it is safe to
	// ignore the returned error from wp methods. Also as our task func never
	// return any error, we have no use returned value from Drain() and don't
	// need to provide an id to Submit().
	for g := 0; g < bCount; g += batchSize {
		from, to := g, g+batchSize
		if to > bCount {
			to = bCount
		}
		ml.wp.Submit("", func(_ context.Context) error {
			for i := from; i < to; i++ {
				offset, skip := getOffsetAndSkip([]byte(backends[i].hashString), uint64(m), ml.SeedMurmur)
				start := i * m
				ml.permutations[start] = offset
				for j := 1; j < m; j++ {
					ml.permutations[start+j] = (ml.permutations[start+(j-1)] + skip) % uint64(m)
				}
			}
			return nil
		})
	}
	ml.wp.Drain()

	return ml.permutations[:bCount*int(m)]
}

func getOffsetAndSkip(addr []byte, m uint64, seed uint32) (uint64, uint64) {
	h1, h2 := murmur3.Hash128(addr, seed)
	offset := h1 % m
	skip := (h2 % (m - 1)) + 1
	return offset, skip
}

// BackendInfo describes the backend information relevant for the maglev
// computation.
type BackendInfo struct {
	ID     loadbalancer.BackendID
	Addr   loadbalancer.L3n4Addr
	Weight uint16

	hashString string
}

// hashString is the string representation of the backend used for both
// sorting and for hashing. To make sure the representation stays stable,
// this method is reproducing parts of Backend.String(), AddrCluster.String(),
// etc.
//
// This MUST NOT be changed as otherwise we may end up with different maglev
// lookup tables on different nodes during upgrades. To introduce a change to
// this we would need to add a new flag to switch to new algorithm to migrate
// new installs over.
func (bi *BackendInfo) setHashString() {
	if bi.hashString != "" {
		return
	}

	var b strings.Builder
	b.WriteByte('[')
	a := bi.Addr
	if a.IsIPv6() {
		b.WriteByte('[')
		b.WriteString(a.AddrCluster.String())
		b.WriteString("]:")
	} else {
		b.WriteString(a.AddrCluster.String())
		b.WriteByte(':')
	}
	b.WriteString(strconv.FormatUint(uint64(a.Port), 10))
	b.WriteByte('/')
	b.WriteString(a.Protocol)
	if a.Scope == loadbalancer.ScopeInternal {
		b.WriteString("/i")
	}
	b.WriteString(",State:active]")
	bi.hashString = b.String()
}

// GetLookupTable returns the Maglev lookup table for the given backends.
// The lookup table contains the IDs of the given backends.
//
// Maglev algorithm might produce different lookup table for the same
// set of backends listed in a different order. To avoid that sort
// backends by the hash, as these are the same on all nodes (in opposite
// to backend IDs which are node-local).
//
// The weights implementation is inspired by https://github.com/envoyproxy/envoy/pull/2982.
//
// A backend weight is honored by altering the frequency how often a backend's turn is
// selected.
// A backend weight is multiplied in each turn by (n + 1) and compared to
// weightCntr[index] value which is an incrementation of weightSum (but starts at
// backend's weight / number of backends, so that each backend is selected at least once). If this is lower
// than weightCntr[index], another backend has a turn (and weightCntr[index]
// is incremented). This way we honor the weights.
func (ml *Maglev) GetLookupTable(backends iter.Seq[BackendInfo]) []loadbalancer.BackendID {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	ml.backendInfosBuffer = ml.backendInfosBuffer[:0]
	for b := range backends {
		b.setHashString()
		ml.backendInfosBuffer = append(ml.backendInfosBuffer, b)
	}

	// Sort the backends by 'hashString'
	slices.SortFunc(
		ml.backendInfosBuffer,
		func(a, b BackendInfo) int {
			return cmp.Compare(a.hashString, b.hashString)
		})

	return ml.computeLookupTable()
}

func (ml *Maglev) computeLookupTable() []loadbalancer.BackendID {
	backends := ml.backendInfosBuffer
	m := uint64(ml.TableSize)

	l := len(backends)
	weightSum := uint64(0)
	weightCntr := make([]float64, l)
	for i, info := range backends {
		weightSum += uint64(info.Weight)
		weightCntr[i] = float64(info.Weight) / float64(l)
	}
	weightsUsed := weightSum/uint64(l) > 1

	perm := ml.getPermutation(backends, runtime.NumCPU())

	next := make([]int, len(backends))
	entry := make([]loadbalancer.BackendID, m)

	const sentinel = 0xffff_ffff
	for j := range m {
		entry[j] = sentinel
	}

	for n := range m {
		i := int(n) % l
		for {
			info := backends[i]
			// change the default selection of backend turns only if weights are used
			if weightsUsed {
				if ((n + 1) * uint64(info.Weight)) < uint64(weightCntr[i]) {
					i = (i + 1) % l
					continue
				}
				weightCntr[i] += float64(weightSum)
			}
			c := perm[i*int(m)+next[i]]
			for entry[c] != sentinel {
				next[i] += 1
				c = perm[i*int(m)+next[i]]
			}
			entry[c] = info.ID
			next[i] += 1
			break
		}
	}
	return entry
}

// derivePermutationSliceLen derives the permutations slice length depending on
// the Maglev table size "m". The formula is (M / 100) * M. The heuristic gives
// the following slice size for the given M.
//
//	251:    0.004806594848632812 MB
//	509:    0.019766311645507812 MB
//	1021:   0.07953193664550783 MB
//	2039:   0.3171936798095703 MB
//	4093:   1.2781256866455077 MB
//	8191:   5.118750076293945 MB
//	16381:  20.472500686645507 MB
//	32749:  81.82502754211426 MB
//	65521:  327.5300171661377 MB
//	131071: 1310.700000076294 MB
//
// Note, this function does not return the MB, but rather returns the number of
// uint64 elements in the slice that equal to the total MB (length). To get the
// MB, multiply by sizeof(uint64).
func derivePermutationSliceLen(m uint64) int {
	return int((m / 100) * m)
}
