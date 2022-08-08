package lvhrunner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func StartQemu(ctx context.Context, rcnf RunConf) error {
	if ext := filepath.Ext(rcnf.TestImage); ext == "" {
		rcnf.TestImage = fmt.Sprintf("%s.qcow2", rcnf.TestImage)
	}

	err := BuildTestImage(rcnf.Logger, &rcnf)
	if err != nil {
		return err
	}

	qemuBin := "qemu-system-x86_64"
	qemuArgs, err := BuildQemuArgs(rcnf.Logger, &rcnf)
	if err != nil {
		return err
	}

	if rcnf.QemuPrint {
		var sb strings.Builder
		sb.WriteString(qemuBin)
		for _, arg := range qemuArgs {
			sb.WriteString(" ")
			if len(arg) > 0 && arg[0] == '-' {
				sb.WriteString("\\\n\t")
			}
			sb.WriteString(arg)
		}

		fmt.Printf("%s\n", sb.String())
		return nil
	}

	// if we don't need to run tests, just exec() so that user will be able to
	// login to the VM.
	if rcnf.JustBoot {
		bin := filepath.Join("/usr/bin/", qemuBin)
		args := []string{qemuBin}
		args = append(args, qemuArgs...)
		env := []string{}
		return unix.Exec(bin, args, env)
	}
	
	qemuCmd := exec.CommandContext(ctx, qemuBin, qemuArgs...)
	qemuCmd.Stdout = os.Stdout
	qemuCmd.Stderr = os.Stderr
	return qemuCmd.Run()
}
