package ebpf

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/btf"
	"github.com/cilium/ebpf/internal/unix"
)

// Errors returned by Map and MapIterator methods.
var (
	ErrKeyNotExist      = errors.New("key does not exist")
	ErrKeyExist         = errors.New("key already exists")
	ErrIterationAborted = errors.New("iteration aborted")
)

// MapOptions control loading a map into the kernel.
type MapOptions struct {
	// The base path to pin maps in if requested via PinByName.
	// Existing maps will be re-used if they are compatible, otherwise an
	// error is returned.
	PinPath string
}

// MapID represents the unique ID of an eBPF map
type MapID uint32

// MapSpec defines a Map.
type MapSpec struct {
	// Name is passed to the kernel as a debug aid. Must only contain
	// alpha numeric and '_' characters.
	Name       string
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32

	// Automatically pin and load a map from MapOptions.PinPath.
	// Generates an error if an existing pinned map is incompatible with the MapSpec.
	Pinning PinType

	// Specify numa node during map creation
	// (effective only if unix.BPF_F_NUMA_NODE flag is set,
	// which can be imported from golang.org/x/sys/unix)
	NumaNode uint32

	// The initial contents of the map. May be nil.
	Contents []MapKV

	// Whether to freeze a map after setting its initial contents.
	Freeze bool

	// InnerMap is used as a template for ArrayOfMaps and HashOfMaps
	InnerMap *MapSpec

	// The BTF associated with this map.
	BTF *btf.Map
}

func (ms *MapSpec) String() string {
	return fmt.Sprintf("%s(keySize=%d, valueSize=%d, maxEntries=%d, flags=%d)", ms.Type, ms.KeySize, ms.ValueSize, ms.MaxEntries, ms.Flags)
}

// Copy returns a copy of the spec.
//
// MapSpec.Contents is a shallow copy.
func (ms *MapSpec) Copy() *MapSpec {
	if ms == nil {
		return nil
	}

	cpy := *ms
	cpy.Contents = make([]MapKV, len(ms.Contents))
	copy(cpy.Contents, ms.Contents)
	cpy.InnerMap = ms.InnerMap.Copy()
	return &cpy
}

// MapKV is used to initialize the contents of a Map.
type MapKV struct {
	Key   interface{}
	Value interface{}
}

func (ms *MapSpec) checkCompatibility(m *Map) error {
	switch {
	case m.typ != ms.Type:
		return fmt.Errorf("expected type %v, got %v", ms.Type, m.typ)

	case m.keySize != ms.KeySize:
		return fmt.Errorf("expected key size %v, got %v", ms.KeySize, m.keySize)

	case m.valueSize != ms.ValueSize:
		return fmt.Errorf("expected value size %v, got %v", ms.ValueSize, m.valueSize)

	case m.maxEntries != ms.MaxEntries:
		return fmt.Errorf("expected max entries %v, got %v", ms.MaxEntries, m.maxEntries)

	case m.flags != ms.Flags:
		return fmt.Errorf("expected flags %v, got %v", ms.Flags, m.flags)
	}
	return nil
}

// Map represents a Map file descriptor.
//
// It is not safe to close a map which is used by other goroutines.
//
// Methods which take interface{} arguments by default encode
// them using binary.Read/Write in the machine's native endianness.
//
// Implement encoding.BinaryMarshaler or encoding.BinaryUnmarshaler
// if you require custom encoding.
type Map struct {
	name       string
	fd         *internal.FD
	typ        MapType
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	flags      uint32
	// Per CPU maps return values larger than the size in the spec
	fullValueSize int
}

// NewMapFromFD creates a map from a raw fd.
//
// You should not use fd after calling this function.
func NewMapFromFD(fd int) (*Map, error) {
	if fd < 0 {
		return nil, errors.New("invalid fd")
	}

	return newMapFromFD(internal.NewFD(uint32(fd)))
}

func newMapFromFD(fd *internal.FD) (*Map, error) {
	info, err := newMapInfoFromFd(fd)
	if err != nil {
		fd.Close()
		return nil, fmt.Errorf("get map info: %s", err)
	}

	return newMap(fd, info.Name, info.Type, info.KeySize, info.ValueSize, info.MaxEntries, info.Flags)
}

// NewMap creates a new Map.
//
// It's equivalent to calling NewMapWithOptions with default options.
func NewMap(spec *MapSpec) (*Map, error) {
	return NewMapWithOptions(spec, MapOptions{})
}

// NewMapWithOptions creates a new Map.
//
// Creating a map for the first time will perform feature detection
// by creating small, temporary maps.
//
// The caller is responsible for ensuring the process' rlimit is set
// sufficiently high for locking memory during map creation. This can be done
// by calling unix.Setrlimit with unix.RLIMIT_MEMLOCK prior to calling NewMapWithOptions.
func NewMapWithOptions(spec *MapSpec, opts MapOptions) (*Map, error) {
	if spec.BTF == nil {
		return newMapWithBTF(spec, nil, opts)
	}

	handle, err := btf.NewHandle(btf.MapSpec(spec.BTF))
	if err != nil && !errors.Is(err, btf.ErrNotSupported) {
		return nil, fmt.Errorf("can't load BTF: %w", err)
	}

	return newMapWithBTF(spec, handle, opts)
}

func newMapWithBTF(spec *MapSpec, handle *btf.Handle, opts MapOptions) (*Map, error) {
	switch spec.Pinning {
	case PinByName:
		if spec.Name == "" || opts.PinPath == "" {
			return nil, fmt.Errorf("pin by name: missing Name or PinPath")
		}

		m, err := LoadPinnedMap(filepath.Join(opts.PinPath, spec.Name))
		if errors.Is(err, unix.ENOENT) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("load pinned map: %s", err)
		}

		if err := spec.checkCompatibility(m); err != nil {
			m.Close()
			return nil, fmt.Errorf("use pinned map %s: %s", spec.Name, err)
		}

		return m, nil

	case PinNone:
		// Nothing to do here

	default:
		return nil, fmt.Errorf("unsupported pin type %d", int(spec.Pinning))
	}

	var innerFd *internal.FD
	if spec.Type == ArrayOfMaps || spec.Type == HashOfMaps {
		if spec.InnerMap == nil {
			return nil, fmt.Errorf("%s requires InnerMap", spec.Type)
		}

		template, err := createMap(spec.InnerMap, nil, handle, opts)
		if err != nil {
			return nil, err
		}
		defer template.Close()

		innerFd = template.fd
	}

	m, err := createMap(spec, innerFd, handle, opts)
	if err != nil {
		return nil, err
	}

	if spec.Pinning == PinByName {
		if err := m.Pin(filepath.Join(opts.PinPath, spec.Name)); err != nil {
			m.Close()
			return nil, fmt.Errorf("pin map: %s", err)
		}
	}

	return m, nil
}

func createMap(spec *MapSpec, inner *internal.FD, handle *btf.Handle, opts MapOptions) (_ *Map, err error) {
	closeOnError := func(closer io.Closer) {
		if err != nil {
			closer.Close()
		}
	}

	spec = spec.Copy()

	switch spec.Type {
	case ArrayOfMaps:
		fallthrough
	case HashOfMaps:
		if err := haveNestedMaps(); err != nil {
			return nil, err
		}

		if spec.ValueSize != 0 && spec.ValueSize != 4 {
			return nil, errors.New("ValueSize must be zero or four for map of map")
		}
		spec.ValueSize = 4

	case PerfEventArray:
		if spec.KeySize != 0 && spec.KeySize != 4 {
			return nil, errors.New("KeySize must be zero or four for perf event array")
		}
		spec.KeySize = 4

		if spec.ValueSize != 0 && spec.ValueSize != 4 {
			return nil, errors.New("ValueSize must be zero or four for perf event array")
		}
		spec.ValueSize = 4

		if spec.MaxEntries == 0 {
			n, err := internal.PossibleCPUs()
			if err != nil {
				return nil, fmt.Errorf("perf event array: %w", err)
			}
			spec.MaxEntries = uint32(n)
		}
	}

	if spec.Flags&(unix.BPF_F_RDONLY_PROG|unix.BPF_F_WRONLY_PROG) > 0 || spec.Freeze {
		if err := haveMapMutabilityModifiers(); err != nil {
			return nil, fmt.Errorf("map create: %w", err)
		}
	}

	attr := bpfMapCreateAttr{
		mapType:    spec.Type,
		keySize:    spec.KeySize,
		valueSize:  spec.ValueSize,
		maxEntries: spec.MaxEntries,
		flags:      spec.Flags,
		numaNode:   spec.NumaNode,
	}

	if inner != nil {
		var err error
		attr.innerMapFd, err = inner.Value()
		if err != nil {
			return nil, fmt.Errorf("map create: %w", err)
		}
	}

	if handle != nil && spec.BTF != nil {
		attr.btfFd = uint32(handle.FD())
		attr.btfKeyTypeID = btf.MapKey(spec.BTF).ID()
		attr.btfValueTypeID = btf.MapValue(spec.BTF).ID()
	}

	if haveObjName() == nil {
		attr.mapName = newBPFObjName(spec.Name)
	}

	fd, err := bpfMapCreate(&attr)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("map create: RLIMIT_MEMLOCK may be too low: %w", err)
		}
		return nil, fmt.Errorf("map create: %w", err)
	}
	defer closeOnError(fd)

	m, err := newMap(fd, spec.Name, spec.Type, spec.KeySize, spec.ValueSize, spec.MaxEntries, spec.Flags)
	if err != nil {
		return nil, err
	}

	if err := m.populate(spec.Contents); err != nil {
		return nil, fmt.Errorf("map create: can't set initial contents: %w", err)
	}

	if spec.Freeze {
		if err := m.Freeze(); err != nil {
			return nil, fmt.Errorf("can't freeze map: %w", err)
		}
	}

	return m, nil
}

func newMap(fd *internal.FD, name string, typ MapType, keySize, valueSize, maxEntries, flags uint32) (*Map, error) {
	m := &Map{
		name,
		fd,
		typ,
		keySize,
		valueSize,
		maxEntries,
		flags,
		int(valueSize),
	}

	if !typ.hasPerCPUValue() {
		return m, nil
	}

	possibleCPUs, err := internal.PossibleCPUs()
	if err != nil {
		return nil, err
	}

	m.fullValueSize = align(int(valueSize), 8) * possibleCPUs
	return m, nil
}

func (m *Map) String() string {
	if m.name != "" {
		return fmt.Sprintf("%s(%s)#%v", m.typ, m.name, m.fd)
	}
	return fmt.Sprintf("%s#%v", m.typ, m.fd)
}

// Type returns the underlying type of the map.
func (m *Map) Type() MapType {
	return m.typ
}

// KeySize returns the size of the map key in bytes.
func (m *Map) KeySize() uint32 {
	return m.keySize
}

// ValueSize returns the size of the map value in bytes.
func (m *Map) ValueSize() uint32 {
	return m.valueSize
}

// MaxEntries returns the maximum number of elements the map can hold.
func (m *Map) MaxEntries() uint32 {
	return m.maxEntries
}

// Flags returns the flags of the map.
func (m *Map) Flags() uint32 {
	return m.flags
}

// Info returns metadata about the map.
func (m *Map) Info() (*MapInfo, error) {
	return newMapInfoFromFd(m.fd)
}

// Lookup retrieves a value from a Map.
//
// Calls Close() on valueOut if it is of type **Map or **Program,
// and *valueOut is not nil.
//
// Returns an error if the key doesn't exist, see IsNotExist.
func (m *Map) Lookup(key, valueOut interface{}) error {
	valuePtr, valueBytes := makeBuffer(valueOut, m.fullValueSize)

	if err := m.lookup(key, valuePtr); err != nil {
		return err
	}

	if valueBytes == nil {
		return nil
	}

	if m.typ.hasPerCPUValue() {
		return unmarshalPerCPUValue(valueOut, int(m.valueSize), valueBytes)
	}

	switch value := valueOut.(type) {
	case **Map:
		m, err := unmarshalMap(valueBytes)
		if err != nil {
			return err
		}

		(*value).Close()
		*value = m
		return nil
	case *Map:
		return fmt.Errorf("can't unmarshal into %T, need %T", value, (**Map)(nil))
	case Map:
		return fmt.Errorf("can't unmarshal into %T, need %T", value, (**Map)(nil))

	case **Program:
		p, err := unmarshalProgram(valueBytes)
		if err != nil {
			return err
		}

		(*value).Close()
		*value = p
		return nil
	case *Program:
		return fmt.Errorf("can't unmarshal into %T, need %T", value, (**Program)(nil))
	case Program:
		return fmt.Errorf("can't unmarshal into %T, need %T", value, (**Program)(nil))

	default:
		return unmarshalBytes(valueOut, valueBytes)
	}
}

// LookupAndDelete retrieves and deletes a value from a Map.
//
// Returns ErrKeyNotExist if the key doesn't exist.
func (m *Map) LookupAndDelete(key, valueOut interface{}) error {
	valuePtr, valueBytes := makeBuffer(valueOut, m.fullValueSize)

	keyPtr, err := marshalPtr(key, int(m.keySize))
	if err != nil {
		return fmt.Errorf("can't marshal key: %w", err)
	}

	if err := bpfMapLookupAndDelete(m.fd, keyPtr, valuePtr); err != nil {
		return fmt.Errorf("lookup and delete failed: %w", err)
	}

	return unmarshalBytes(valueOut, valueBytes)
}

// LookupBytes gets a value from Map.
//
// Returns a nil value if a key doesn't exist.
func (m *Map) LookupBytes(key interface{}) ([]byte, error) {
	valueBytes := make([]byte, m.fullValueSize)
	valuePtr := internal.NewSlicePointer(valueBytes)

	err := m.lookup(key, valuePtr)
	if errors.Is(err, ErrKeyNotExist) {
		return nil, nil
	}

	return valueBytes, err
}

func (m *Map) lookup(key interface{}, valueOut internal.Pointer) error {
	keyPtr, err := marshalPtr(key, int(m.keySize))
	if err != nil {
		return fmt.Errorf("can't marshal key: %w", err)
	}

	if err = bpfMapLookupElem(m.fd, keyPtr, valueOut); err != nil {
		return fmt.Errorf("lookup failed: %w", err)
	}
	return nil
}

// MapUpdateFlags controls the behaviour of the Map.Update call.
//
// The exact semantics depend on the specific MapType.
type MapUpdateFlags uint64

const (
	// UpdateAny creates a new element or update an existing one.
	UpdateAny MapUpdateFlags = iota
	// UpdateNoExist creates a new element.
	UpdateNoExist MapUpdateFlags = 1 << (iota - 1)
	// UpdateExist updates an existing element.
	UpdateExist
)

// Put replaces or creates a value in map.
//
// It is equivalent to calling Update with UpdateAny.
func (m *Map) Put(key, value interface{}) error {
	return m.Update(key, value, UpdateAny)
}

// Update changes the value of a key.
func (m *Map) Update(key, value interface{}, flags MapUpdateFlags) error {
	keyPtr, err := marshalPtr(key, int(m.keySize))
	if err != nil {
		return fmt.Errorf("can't marshal key: %w", err)
	}

	var valuePtr internal.Pointer
	if m.typ.hasPerCPUValue() {
		valuePtr, err = marshalPerCPUValue(value, int(m.valueSize))
	} else {
		valuePtr, err = marshalPtr(value, int(m.valueSize))
	}
	if err != nil {
		return fmt.Errorf("can't marshal value: %w", err)
	}

	if err = bpfMapUpdateElem(m.fd, keyPtr, valuePtr, uint64(flags)); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	return nil
}

// Delete removes a value.
//
// Returns ErrKeyNotExist if the key does not exist.
func (m *Map) Delete(key interface{}) error {
	keyPtr, err := marshalPtr(key, int(m.keySize))
	if err != nil {
		return fmt.Errorf("can't marshal key: %w", err)
	}

	if err = bpfMapDeleteElem(m.fd, keyPtr); err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}
	return nil
}

// NextKey finds the key following an initial key.
//
// See NextKeyBytes for details.
//
// Returns ErrKeyNotExist if there is no next key.
func (m *Map) NextKey(key, nextKeyOut interface{}) error {
	nextKeyPtr, nextKeyBytes := makeBuffer(nextKeyOut, int(m.keySize))

	if err := m.nextKey(key, nextKeyPtr); err != nil {
		return err
	}

	if nextKeyBytes == nil {
		return nil
	}

	if err := unmarshalBytes(nextKeyOut, nextKeyBytes); err != nil {
		return fmt.Errorf("can't unmarshal next key: %w", err)
	}
	return nil
}

// NextKeyBytes returns the key following an initial key as a byte slice.
//
// Passing nil will return the first key.
//
// Use Iterate if you want to traverse all entries in the map.
//
// Returns nil if there are no more keys.
func (m *Map) NextKeyBytes(key interface{}) ([]byte, error) {
	nextKey := make([]byte, m.keySize)
	nextKeyPtr := internal.NewSlicePointer(nextKey)

	err := m.nextKey(key, nextKeyPtr)
	if errors.Is(err, ErrKeyNotExist) {
		return nil, nil
	}

	return nextKey, err
}

func (m *Map) nextKey(key interface{}, nextKeyOut internal.Pointer) error {
	var (
		keyPtr internal.Pointer
		err    error
	)

	if key != nil {
		keyPtr, err = marshalPtr(key, int(m.keySize))
		if err != nil {
			return fmt.Errorf("can't marshal key: %w", err)
		}
	}

	if err = bpfMapGetNextKey(m.fd, keyPtr, nextKeyOut); err != nil {
		return fmt.Errorf("next key failed: %w", err)
	}
	return nil
}

// Iterate traverses a map.
//
// It's safe to create multiple iterators at the same time.
//
// It's not possible to guarantee that all keys in a map will be
// returned if there are concurrent modifications to the map.
func (m *Map) Iterate() *MapIterator {
	return newMapIterator(m)
}

// Close removes a Map
func (m *Map) Close() error {
	if m == nil {
		// This makes it easier to clean up when iterating maps
		// of maps / programs.
		return nil
	}

	return m.fd.Close()
}

// FD gets the file descriptor of the Map.
//
// Calling this function is invalid after Close has been called.
func (m *Map) FD() int {
	fd, err := m.fd.Value()
	if err != nil {
		// Best effort: -1 is the number most likely to be an
		// invalid file descriptor.
		return -1
	}

	return int(fd)
}

// Clone creates a duplicate of the Map.
//
// Closing the duplicate does not affect the original, and vice versa.
// Changes made to the map are reflected by both instances however.
//
// Cloning a nil Map returns nil.
func (m *Map) Clone() (*Map, error) {
	if m == nil {
		return nil, nil
	}

	dup, err := m.fd.Dup()
	if err != nil {
		return nil, fmt.Errorf("can't clone map: %w", err)
	}

	return &Map{
		m.name,
		dup,
		m.typ,
		m.keySize,
		m.valueSize,
		m.maxEntries,
		m.flags,
		m.fullValueSize,
	}, nil
}

// Pin persists the map past the lifetime of the process that created it.
//
// This requires bpffs to be mounted above fileName. See https://docs.cilium.io/en/k8s-doc/admin/#admin-mount-bpffs
func (m *Map) Pin(fileName string) error {
	return internal.BPFObjPin(fileName, m.fd)
}

// Freeze prevents a map to be modified from user space.
//
// It makes no changes to kernel-side restrictions.
func (m *Map) Freeze() error {
	if err := haveMapMutabilityModifiers(); err != nil {
		return fmt.Errorf("can't freeze map: %w", err)
	}

	if err := bpfMapFreeze(m.fd); err != nil {
		return fmt.Errorf("can't freeze map: %w", err)
	}
	return nil
}

func (m *Map) populate(contents []MapKV) error {
	for _, kv := range contents {
		if err := m.Put(kv.Key, kv.Value); err != nil {
			return fmt.Errorf("key %v: %w", kv.Key, err)
		}
	}
	return nil
}

// LoadPinnedMap load a Map from a BPF file.
func LoadPinnedMap(fileName string) (*Map, error) {
	fd, err := internal.BPFObjGet(fileName)
	if err != nil {
		return nil, err
	}

	return newMapFromFD(fd)
}

func unmarshalMap(buf []byte) (*Map, error) {
	if len(buf) != 4 {
		return nil, errors.New("map id requires 4 byte value")
	}

	// Looking up an entry in a nested map or prog array returns an id,
	// not an fd.
	id := internal.NativeEndian.Uint32(buf)
	return NewMapFromID(MapID(id))
}

// MarshalBinary implements BinaryMarshaler.
func (m *Map) MarshalBinary() ([]byte, error) {
	fd, err := m.fd.Value()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4)
	internal.NativeEndian.PutUint32(buf, fd)
	return buf, nil
}

func patchValue(value []byte, typ btf.Type, replacements map[string]interface{}) error {
	replaced := make(map[string]bool)
	replace := func(name string, offset, size int, replacement interface{}) error {
		if offset+size > len(value) {
			return fmt.Errorf("%s: offset %d(+%d) is out of bounds", name, offset, size)
		}

		buf, err := marshalBytes(replacement, size)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", name, err)
		}

		copy(value[offset:offset+size], buf)
		replaced[name] = true
		return nil
	}

	switch parent := typ.(type) {
	case *btf.Datasec:
		for _, secinfo := range parent.Vars {
			name := string(secinfo.Type.(*btf.Var).Name)
			replacement, ok := replacements[name]
			if !ok {
				continue
			}

			err := replace(name, int(secinfo.Offset), int(secinfo.Size), replacement)
			if err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("patching %T is not supported", typ)
	}

	if len(replaced) == len(replacements) {
		return nil
	}

	var missing []string
	for name := range replacements {
		if !replaced[name] {
			missing = append(missing, name)
		}
	}

	if len(missing) == 1 {
		return fmt.Errorf("unknown field: %s", missing[0])
	}

	return fmt.Errorf("unknown fields: %s", strings.Join(missing, ","))
}

// MapIterator iterates a Map.
//
// See Map.Iterate.
type MapIterator struct {
	target            *Map
	prevKey           interface{}
	prevBytes         []byte
	count, maxEntries uint32
	done              bool
	err               error
}

func newMapIterator(target *Map) *MapIterator {
	return &MapIterator{
		target:     target,
		maxEntries: target.maxEntries,
		prevBytes:  make([]byte, target.keySize),
	}
}

// Next decodes the next key and value.
//
// Iterating a hash map from which keys are being deleted is not
// safe. You may see the same key multiple times. Iteration may
// also abort with an error, see IsIterationAborted.
//
// Returns false if there are no more entries. You must check
// the result of Err afterwards.
//
// See Map.Get for further caveats around valueOut.
func (mi *MapIterator) Next(keyOut, valueOut interface{}) bool {
	if mi.err != nil || mi.done {
		return false
	}

	for ; mi.count < mi.maxEntries; mi.count++ {
		var nextBytes []byte
		nextBytes, mi.err = mi.target.NextKeyBytes(mi.prevKey)
		if mi.err != nil {
			return false
		}

		if nextBytes == nil {
			mi.done = true
			return false
		}

		// The user can get access to nextBytes since unmarshalBytes
		// does not copy when unmarshaling into a []byte.
		// Make a copy to prevent accidental corruption of
		// iterator state.
		copy(mi.prevBytes, nextBytes)
		mi.prevKey = mi.prevBytes

		mi.err = mi.target.Lookup(nextBytes, valueOut)
		if errors.Is(mi.err, ErrKeyNotExist) {
			// Even though the key should be valid, we couldn't look up
			// its value. If we're iterating a hash map this is probably
			// because a concurrent delete removed the value before we
			// could get it. This means that the next call to NextKeyBytes
			// is very likely to restart iteration.
			// If we're iterating one of the fd maps like
			// ProgramArray it means that a given slot doesn't have
			// a valid fd associated. It's OK to continue to the next slot.
			continue
		}
		if mi.err != nil {
			return false
		}

		mi.err = unmarshalBytes(keyOut, nextBytes)
		return mi.err == nil
	}

	mi.err = fmt.Errorf("%w", ErrIterationAborted)
	return false
}

// Err returns any encountered error.
//
// The method must be called after Next returns nil.
//
// Returns ErrIterationAborted if it wasn't possible to do a full iteration.
func (mi *MapIterator) Err() error {
	return mi.err
}

// MapGetNextID returns the ID of the next eBPF map.
//
// Returns ErrNotExist, if there is no next eBPF map.
func MapGetNextID(startID MapID) (MapID, error) {
	id, err := objGetNextID(internal.BPF_MAP_GET_NEXT_ID, uint32(startID))
	return MapID(id), err
}

// NewMapFromID returns the map for a given id.
//
// Returns ErrNotExist, if there is no eBPF map with the given id.
func NewMapFromID(id MapID) (*Map, error) {
	fd, err := bpfObjGetFDByID(internal.BPF_MAP_GET_FD_BY_ID, uint32(id))
	if err != nil {
		return nil, err
	}

	return newMapFromFD(fd)
}

// ID returns the systemwide unique ID of the map.
//
// Requires at least Linux 4.13.
func (m *Map) ID() (MapID, error) {
	info, err := bpfGetMapInfoByFD(m.fd)
	if err != nil {
		return MapID(0), err
	}
	return MapID(info.id), nil
}
