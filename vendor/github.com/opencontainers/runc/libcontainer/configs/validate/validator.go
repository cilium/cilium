package validate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
	selinux "github.com/opencontainers/selinux/go-selinux"
)

type Validator interface {
	Validate(*configs.Config) error
}

func New() Validator {
	return &ConfigValidator{}
}

type ConfigValidator struct {
}

func (v *ConfigValidator) Validate(config *configs.Config) error {
	if err := v.rootfs(config); err != nil {
		return err
	}
	if err := v.network(config); err != nil {
		return err
	}
	if err := v.hostname(config); err != nil {
		return err
	}
	if err := v.security(config); err != nil {
		return err
	}
	if err := v.usernamespace(config); err != nil {
		return err
	}
	if err := v.sysctl(config); err != nil {
		return err
	}
	if config.Rootless {
		if err := v.rootless(config); err != nil {
			return err
		}
	}
	return nil
}

// rootfs validates if the rootfs is an absolute path and is not a symlink
// to the container's root filesystem.
func (v *ConfigValidator) rootfs(config *configs.Config) error {
	if _, err := os.Stat(config.Rootfs); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rootfs (%s) does not exist", config.Rootfs)
		}
		return err
	}
	cleaned, err := filepath.Abs(config.Rootfs)
	if err != nil {
		return err
	}
	if cleaned, err = filepath.EvalSymlinks(cleaned); err != nil {
		return err
	}
	if filepath.Clean(config.Rootfs) != cleaned {
		return fmt.Errorf("%s is not an absolute path or is a symlink", config.Rootfs)
	}
	return nil
}

func (v *ConfigValidator) network(config *configs.Config) error {
	if !config.Namespaces.Contains(configs.NEWNET) {
		if len(config.Networks) > 0 || len(config.Routes) > 0 {
			return fmt.Errorf("unable to apply network settings without a private NET namespace")
		}
	}
	return nil
}

func (v *ConfigValidator) hostname(config *configs.Config) error {
	if config.Hostname != "" && !config.Namespaces.Contains(configs.NEWUTS) {
		return fmt.Errorf("unable to set hostname without a private UTS namespace")
	}
	return nil
}

func (v *ConfigValidator) security(config *configs.Config) error {
	// restrict sys without mount namespace
	if (len(config.MaskPaths) > 0 || len(config.ReadonlyPaths) > 0) &&
		!config.Namespaces.Contains(configs.NEWNS) {
		return fmt.Errorf("unable to restrict sys entries without a private MNT namespace")
	}
	if config.ProcessLabel != "" && !selinux.GetEnabled() {
		return fmt.Errorf("selinux label is specified in config, but selinux is disabled or not supported")
	}

	return nil
}

func (v *ConfigValidator) usernamespace(config *configs.Config) error {
	if config.Namespaces.Contains(configs.NEWUSER) {
		if _, err := os.Stat("/proc/self/ns/user"); os.IsNotExist(err) {
			return fmt.Errorf("USER namespaces aren't enabled in the kernel")
		}
	} else {
		if config.UidMappings != nil || config.GidMappings != nil {
			return fmt.Errorf("User namespace mappings specified, but USER namespace isn't enabled in the config")
		}
	}
	return nil
}

// sysctl validates that the specified sysctl keys are valid or not.
// /proc/sys isn't completely namespaced and depending on which namespaces
// are specified, a subset of sysctls are permitted.
func (v *ConfigValidator) sysctl(config *configs.Config) error {
	validSysctlMap := map[string]bool{
		"kernel.msgmax":          true,
		"kernel.msgmnb":          true,
		"kernel.msgmni":          true,
		"kernel.sem":             true,
		"kernel.shmall":          true,
		"kernel.shmmax":          true,
		"kernel.shmmni":          true,
		"kernel.shm_rmid_forced": true,
	}

	for s := range config.Sysctl {
		if validSysctlMap[s] || strings.HasPrefix(s, "fs.mqueue.") {
			if config.Namespaces.Contains(configs.NEWIPC) {
				continue
			} else {
				return fmt.Errorf("sysctl %q is not allowed in the hosts ipc namespace", s)
			}
		}
		if strings.HasPrefix(s, "net.") {
			if config.Namespaces.Contains(configs.NEWNET) {
				if path := config.Namespaces.PathOf(configs.NEWNET); path != "" {
					if err := checkHostNs(s, path); err != nil {
						return err
					}
				}
				continue
			} else {
				return fmt.Errorf("sysctl %q is not allowed in the hosts network namespace", s)
			}
		}
		return fmt.Errorf("sysctl %q is not in a separate kernel namespace", s)
	}

	return nil
}

func isSymbolicLink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}

	return fi.Mode()&os.ModeSymlink == os.ModeSymlink, nil
}

// checkHostNs checks whether network sysctl is used in host namespace.
func checkHostNs(sysctlConfig string, path string) error {
	var currentProcessNetns = "/proc/self/ns/net"
	// readlink on the current processes network namespace
	destOfCurrentProcess, err := os.Readlink(currentProcessNetns)
	if err != nil {
		return fmt.Errorf("read soft link %q error", currentProcessNetns)
	}

	// First check if the provided path is a symbolic link
	symLink, err := isSymbolicLink(path)
	if err != nil {
		return fmt.Errorf("could not check that %q is a symlink: %v", path, err)
	}

	if symLink == false {
		// The provided namespace is not a symbolic link,
		// it is not the host namespace.
		return nil
	}

	// readlink on the path provided in the struct
	destOfContainer, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("read soft link %q error", path)
	}
	if destOfContainer == destOfCurrentProcess {
		return fmt.Errorf("sysctl %q is not allowed in the hosts network namespace", sysctlConfig)
	}
	return nil
}
