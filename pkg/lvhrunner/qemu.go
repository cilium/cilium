package lvhrunner

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func BuildQemuArgs(log *logrus.Logger, rcnf *RunConf) ([]string, error) {
	qemuArgs := []string{
		// no need for all the default devices
		"-nodefaults",
		// no need display (-nographics seems a bit slower)
		"-display", "none",
		// don't reboot, just exit
		"-no-reboot",
		// cpus, memory
		"-smp", "2", "-m", "4G",
	}

	// quick-and-dirty kvm detection
	if !rcnf.DisableKVM {
		if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0755); err == nil {
			qemuArgs = append(qemuArgs, "-enable-kvm", "-cpu", "kvm64")
			f.Close()
		} else {
			log.Info("KVM disabled")
		}
	}

	qemuArgs = append(qemuArgs,
		"-hda", rcnf.testImageFname(),
	)

	if rcnf.KernelFname != "" {
		appendArgs := []string{
			"root=/dev/sda",
			"console=ttyS0",
			"earlyprintk=ttyS0",
			"panic=-1",
		}
		// if rcnf.UseCiliumTesterInit {
		// 	appendArgs = append(appendArgs, fmt.Sprintf("init=%s", CiliumTesterBin))
		// }
		qemuArgs = append(qemuArgs,
			"-kernel", rcnf.KernelFname,
			"-append", fmt.Sprintf("%s", strings.Join(appendArgs, " ")),
		)
	}

	if !rcnf.DisableNetwork {
		qemuArgs = append(qemuArgs,
			"-netdev", "user,id=user.0,hostfwd=tcp::2222-:22",
			"-device", "virtio-net-pci,netdev=user.0",
		)
	}

	// NB: not sure what the best option is here, this is from trial-and-error
	if !rcnf.Daemonize {
		qemuArgs = append(qemuArgs,
			"-serial", "mon:stdio",
			"-device", "virtio-serial-pci",
		)
	} else {
		qemuArgs = append(qemuArgs, "-daemonize")
	}

	for _, fs := range rcnf.Filesystems {
		qemuArgs = append(qemuArgs, fs.QemuArgs()...)
	}

	return qemuArgs, nil
}
