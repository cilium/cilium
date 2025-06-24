package btf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/platform"
)

// globalCache amortises decoding BTF across all users of the library.
var globalCache = struct {
	sync.RWMutex
	kernel  *Spec
	modules map[string]*Spec
}{
	modules: make(map[string]*Spec),
}

// FlushKernelSpec removes any cached kernel type information.
func FlushKernelSpec() {
	globalCache.Lock()
	defer globalCache.Unlock()

	globalCache.kernel = nil
	globalCache.modules = make(map[string]*Spec)
}

// LoadKernelSpec returns the current kernel's BTF information.
//
// Defaults to /sys/kernel/btf/vmlinux and falls back to scanning the file system
// for vmlinux ELFs. Returns an error wrapping ErrNotSupported if BTF is not enabled.
//
// Consider using [Cache] instead.
func LoadKernelSpec() (*Spec, error) {
	spec, err := loadCachedKernelSpec()
	return spec.Copy(), err
}

// load (and cache) the kernel spec.
//
// Does not copy Spec.
func loadCachedKernelSpec() (*Spec, error) {
	globalCache.RLock()
	spec := globalCache.kernel
	globalCache.RUnlock()

	if spec != nil {
		return spec, nil
	}

	globalCache.Lock()
	defer globalCache.Unlock()

	spec, err := loadKernelSpec()
	if err != nil {
		return nil, err
	}

	globalCache.kernel = spec
	return spec, nil
}

// LoadKernelModuleSpec returns the BTF information for the named kernel module.
//
// Using [Cache.Module] is faster when loading BTF for more than one module.
//
// Defaults to /sys/kernel/btf/<module>.
// Returns an error wrapping ErrNotSupported if BTF is not enabled.
// Returns an error wrapping fs.ErrNotExist if BTF for the specific module doesn't exist.
func LoadKernelModuleSpec(module string) (*Spec, error) {
	spec, err := loadCachedKernelModuleSpec(module)
	return spec.Copy(), err
}

// load (and cache) a module spec.
//
// Does not copy Spec.
func loadCachedKernelModuleSpec(module string) (*Spec, error) {
	globalCache.RLock()
	spec := globalCache.modules[module]
	globalCache.RUnlock()

	if spec != nil {
		return spec, nil
	}

	base, err := loadCachedKernelSpec()
	if err != nil {
		return nil, err
	}

	// NB: This only allows a single module to be parsed at a time. Not sure
	// it makes a difference.
	globalCache.Lock()
	defer globalCache.Unlock()

	spec, err = loadKernelModuleSpec(module, base)
	if err != nil {
		return nil, err
	}

	globalCache.modules[module] = spec
	return spec, nil
}

func loadKernelSpec() (_ *Spec, _ error) {
	if platform.IsWindows {
		return nil, internal.ErrNotSupportedOnOS
	}

	fh, err := os.Open("/sys/kernel/btf/vmlinux")
	if err == nil {
		defer fh.Close()

		spec, err := loadRawSpec(fh, internal.NativeEndian, nil)
		return spec, err
	}

	file, err := findVMLinux()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	spec, err := LoadSpecFromReader(file)
	return spec, err
}

func loadKernelModuleSpec(module string, base *Spec) (*Spec, error) {
	if platform.IsWindows {
		return nil, internal.ErrNotSupportedOnOS
	}

	dir, file := filepath.Split(module)
	if dir != "" || filepath.Ext(file) != "" {
		return nil, fmt.Errorf("invalid module name %q", module)
	}

	fh, err := os.Open(filepath.Join("/sys/kernel/btf", module))
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	return loadRawSpec(fh, internal.NativeEndian, base)
}

// findVMLinux scans multiple well-known paths for vmlinux kernel images.
func findVMLinux() (*os.File, error) {
	if platform.IsWindows {
		return nil, fmt.Errorf("find vmlinux: %w", internal.ErrNotSupportedOnOS)
	}

	release, err := linux.KernelRelease()
	if err != nil {
		return nil, err
	}

	// use same list of locations as libbpf
	// https://github.com/libbpf/libbpf/blob/9a3a42608dbe3731256a5682a125ac1e23bced8f/src/btf.c#L3114-L3122
	locations := []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	}

	for _, loc := range locations {
		file, err := os.Open(fmt.Sprintf(loc, release))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return file, err
	}

	return nil, fmt.Errorf("no BTF found for kernel version %s: %w", release, internal.ErrNotSupported)
}

// Cache allows to amortise the cost of decoding BTF across multiple call-sites.
//
// It is not safe for concurrent use.
type Cache struct {
	KernelTypes   *Spec
	ModuleTypes   map[string]*Spec
	LoadedModules []string
}

// NewCache creates a new Cache.
//
// Opportunistically reuses a global cache if possible.
func NewCache() *Cache {
	globalCache.RLock()
	defer globalCache.RUnlock()

	// This copy is either a no-op or very cheap, since the spec won't contain
	// any inflated types.
	kernel := globalCache.kernel.Copy()
	if kernel == nil {
		return &Cache{}
	}

	modules := make(map[string]*Spec, len(globalCache.modules))
	for name, spec := range globalCache.modules {
		decoder, _ := rebaseDecoder(spec.decoder, kernel.decoder)
		// NB: Kernel module BTF can't contain ELF fixups because it is always
		// read from sysfs.
		modules[name] = &Spec{decoder: decoder}
	}

	if len(modules) == 0 {
		return &Cache{kernel, nil, nil}
	}

	return &Cache{kernel, modules, nil}
}

// Kernel is equivalent to [LoadKernelSpec], except that repeated calls do
// not copy the Spec.
func (c *Cache) Kernel() (*Spec, error) {
	if c.KernelTypes != nil {
		return c.KernelTypes, nil
	}

	var err error
	c.KernelTypes, err = LoadKernelSpec()
	return c.KernelTypes, err
}

// Module is equivalent to [LoadKernelModuleSpec], except that repeated calls do
// not copy the spec.
//
// All modules also share the return value of [Kernel] as their base.
func (c *Cache) Module(name string) (*Spec, error) {
	if spec := c.ModuleTypes[name]; spec != nil {
		return spec, nil
	}

	if c.ModuleTypes == nil {
		c.ModuleTypes = make(map[string]*Spec)
	}

	base, err := c.Kernel()
	if err != nil {
		return nil, err
	}

	spec, err := loadCachedKernelModuleSpec(name)
	if err != nil {
		return nil, err
	}

	// Important: base is shared between modules. This allows inflating common
	// types only once.
	decoder, err := rebaseDecoder(spec.decoder, base.decoder)
	if err != nil {
		return nil, err
	}

	spec = &Spec{decoder: decoder}
	c.ModuleTypes[name] = spec
	return spec, err
}

// Modules returns a sorted list of all loaded modules.
func (c *Cache) Modules() ([]string, error) {
	if c.LoadedModules != nil {
		return c.LoadedModules, nil
	}

	btfDir, err := os.Open("/sys/kernel/btf")
	if err != nil {
		return nil, err
	}
	defer btfDir.Close()

	entries, err := btfDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	entries = slices.DeleteFunc(entries, func(s string) bool {
		return s == "vmlinux"
	})

	sort.Strings(entries)
	c.LoadedModules = entries
	return entries, nil
}
