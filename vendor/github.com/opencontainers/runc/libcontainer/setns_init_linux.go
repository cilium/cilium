// +build linux

package libcontainer

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/keys"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/selinux/go-selinux/label"

	"golang.org/x/sys/unix"
)

// linuxSetnsInit performs the container's initialization for running a new process
// inside an existing container.
type linuxSetnsInit struct {
	pipe          *os.File
	consoleSocket *os.File
	config        *initConfig
}

func (l *linuxSetnsInit) getSessionRingName() string {
	return fmt.Sprintf("_ses.%s", l.config.ContainerId)
}

func (l *linuxSetnsInit) Init() error {
	if !l.config.Config.NoNewKeyring {
		// do not inherit the parent's session keyring
		if _, err := keys.JoinSessionKeyring(l.getSessionRingName()); err != nil {
			return err
		}
	}
	if l.config.CreateConsole {
		if err := setupConsole(l.consoleSocket, l.config, false); err != nil {
			return err
		}
		if err := system.Setctty(); err != nil {
			return err
		}
	}
	if l.config.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
	}
	if l.config.Config.Seccomp != nil {
		if err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return err
		}
	}
	if err := finalizeNamespace(l.config); err != nil {
		return err
	}
	if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
		return err
	}
	if err := label.SetProcessLabel(l.config.ProcessLabel); err != nil {
		return err
	}
	return system.Execv(l.config.Args[0], l.config.Args[0:], os.Environ())
}
