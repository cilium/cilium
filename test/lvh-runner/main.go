package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/lvhrunner"
	"github.com/cilium/little-vm-helper/pkg/images"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func main() {
	var (
		rcnf lvhrunner.RunConf

		mounts []string
	)

	// Remove "mmdebstrap" from the list of required binaries since we don't need it to run or modify images
	images.Binaries = []string{
		images.QemuImg,
		images.VirtCustomize,
		images.GuestFish,
	}

	cmd := &cobra.Command{
		Use:          "vmtest-run",
		Short:        "vmtest-run: helper to run Cilium tests on VMs",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			rcnf.Logger = logrus.New()
			if err := images.CheckEnvironment(); err != nil {
				return err
			}

			var err error
			rcnf.Filesystems, err = parseMounts(mounts)
			if err != nil {
				return fmt.Errorf("Mount flags: %w", err)
			}
			// if cwd, err := os.Getwd(); err == nil {
			// 	rcnf.Filesystems = append(rcnf.Filesystems,
			// 		&lvhrunner.VirtIOFilesystem{
			// 			ID:      "cilium",
			// 			Hostdir: cwd,
			// 			VMdir:   cwd,
			// 		},
			// 	)
			// } else {
			// 	return fmt.Errorf("failed to get cwd: %w", err)
			// }

			t0 := time.Now()

			ctx := context.Background()
			ctx, cancel := signal.NotifyContext(ctx, unix.SIGINT, unix.SIGTERM)
			defer cancel()

			err = lvhrunner.StartQemu(ctx, rcnf)
			dur := time.Since(t0).Round(time.Millisecond)
			fmt.Printf("Execution took %v\n", dur)
			if err != nil {
				return fmt.Errorf("Qemu exited with an error: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&rcnf.BaseFname, "base", "", "base image filename")
	cmd.MarkFlagRequired("base")
	cmd.Flags().StringVar(&rcnf.TestImage, "name", "cilium", "new vm (and basis for the image name). New vm image will be in the directory of the base image")
	cmd.Flags().StringVar(&rcnf.KernelFname, "kernel", "", "kernel filename to boot with. (if empty no -kernel option will be passed to qemu)")
	cmd.Flags().BoolVar(&rcnf.DontRebuildImage, "dont-rebuild-image", false, "dont rebuild image")
	cmd.Flags().BoolVar(&rcnf.QemuPrint, "qemu-cmd-print", false, "Do not run the qemu command, just print it")
	cmd.Flags().BoolVar(&rcnf.DisableKVM, "qemu-disable-kvm", false, "Do not use KVM acceleration, even if /dev/kvm exists")
	cmd.Flags().BoolVar(&rcnf.JustBoot, "just-boot", false, "Do not actually run any tests. Just setup everything and start the VM. User will be able to login to the VM.")
	cmd.Flags().StringArrayVarP(&mounts, "mount", "m", nil, "Mount a directory (id:path[:vmpath])")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseMounts(flags []string) ([]lvhrunner.QemuFS, error) {
	var qfs []lvhrunner.QemuFS
	for _, flag := range flags {
		id, paths, found := strings.Cut(flag, ":")
		if !found {
			return nil, fmt.Errorf(
				"mount flag '%s' doesn't contain a id, must be <id>:<hostpath> or <id>:<hostpath>:<vmpath>",
				flag,
			)
		}

		hostPath, vmPath, found := strings.Cut(paths, ":")
		if !found {
			hostPath = paths
			vmPath = paths
		}

		if strings.HasPrefix(hostPath, "~") || strings.HasPrefix(vmPath, "~") {
			homedir, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}

			hostPath = strings.Replace(hostPath, "~", homedir, 1)
			vmPath = strings.Replace(vmPath, "~", homedir, 1)
		}

		var err error
		hostPath, err = filepath.Abs(hostPath)
		if err != nil {
			return nil, fmt.Errorf(
				"mount flag '%s': %w",
				flag,
				err,
			)
		}

		vmPath, err = filepath.Abs(vmPath)
		if err != nil {
			return nil, fmt.Errorf(
				"mount flag '%s': %w",
				flag,
				err,
			)
		}

		qfs = append(qfs, &lvhrunner.VirtIOFilesystem{
			ID:      id,
			Hostdir: hostPath,
			VMdir:   vmPath,
		})
	}

	return qfs, nil
}

var ciliumTesterService = `
[Unit]
Description=Cilium tester
After=network.target

[Service]
ExecStart=%s
Type=oneshot
# https://www.freedesktop.org/software/systemd/man/systemd.exec.html
# StandardOutput=file:%s
StandardOutput=tty
# StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
`

var (
	CiliumTesterBin   = "./testing/cilium-tester"
	CiliumTesterVmDir = "/sbin"
	CiliumTesterVmBin = filepath.Join(CiliumTesterVmDir, filepath.Base(CiliumTesterBin))
)

func BuildTesterService(rcnf *lvhrunner.RunConf, tmpDir string) ([]images.Action, error) {
	service := fmt.Sprintf(ciliumTesterService, CiliumTesterVmBin, rcnf.TesterOut)
	var b bytes.Buffer
	b.WriteString(service)

	tmpFile := filepath.Join(tmpDir, "cilium-tester.service")
	err := os.WriteFile(tmpFile, b.Bytes(), 0722)
	if err != nil {
		return nil, err
	}

	actions := []images.Action{
		{Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: "/etc/systemd/system",
		}},
		/*
			{Op: &images.RunCommand{
				Cmd: "sed -i  's/^#LogColor=yes/LogColor=no/' /etc/systemd/system.conf",
			}},
		*/
	}

	if !rcnf.JustBoot {
		enableTester := images.Action{Op: &images.RunCommand{Cmd: "systemctl enable cilium-tester.service"}}
		actions = append(actions, enableTester)
	}

	return actions, nil
}
