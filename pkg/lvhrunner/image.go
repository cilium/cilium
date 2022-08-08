package lvhrunner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/sirupsen/logrus"
)

func BuildFilesystemActions(fs []QemuFS, tmpDir string) ([]images.Action, error) {

	actions := make([]images.Action, 0, len(fs)+1)

	var b bytes.Buffer
	for _, fs := range fs {
		b.WriteString(fs.FStabEntry())
		act := images.Action{
			Op: &images.MkdirCommand{Dir: fs.VMMountpoint()},
		}
		actions = append(actions, act)
	}

	// NB: this is so that init can remount / rw
	b.WriteString("/dev/root\t/\text4\terrors=remount-ro\t0\t1\n")

	tmpFile := filepath.Join(tmpDir, "fstab")
	err := os.WriteFile(tmpFile, b.Bytes(), 0722)
	if err != nil {
		return nil, err
	}

	actions = append(actions, images.Action{
		Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: "/etc",
		},
	})

	return actions, nil
}


// func BuildTesterActions(rcnf *RunConf, tmpDir string) ([]images.Action, error) {

// 	confB, err := json.MarshalIndent(&rcnf.TesterConf, "", "    ")
// 	if err != nil {
// 		return nil, err
// 	}

// 	tmpConfFile := filepath.Join(tmpDir, filepath.Base(vmtests.ConfFile))
// 	remoteConfDir := filepath.Dir(vmtests.ConfFile)
// 	if err := os.WriteFile(tmpConfFile, confB, 0722); err != nil {
// 		return nil, err
// 	}

// 	ret := []images.Action{
// 		{Op: &images.CopyInCommand{LocalPath: CiliumTesterBin, RemoteDir: "/sbin"}},
// 		{Op: &images.CopyInCommand{LocalPath: tmpConfFile, RemoteDir: remoteConfDir}},
// 	}

// 	if !rcnf.UseCiliumTesterInit {
// 		acts, err := BuildTesterService(rcnf, tmpDir)
// 		if err != nil {
// 			return nil, err
// 		}
// 		ret = append(ret, acts...)
// 	}

// 	return ret, nil
// }

func BuildTestImage(log *logrus.Logger, rcnf *RunConf) error {

	imagesDir, baseImage := filepath.Split(rcnf.BaseFname)
	hostname := strings.TrimSuffix(rcnf.TestImage, filepath.Ext(rcnf.TestImage))

	tmpDir, err := os.MkdirTemp("", "cilium-vmtests-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	fsActions, err := BuildFilesystemActions(rcnf.Filesystems, tmpDir)
	if err != nil {
		return err
	}

	// testerActions, err := BuildTesterActions(rcnf, tmpDir)
	// if err != nil {
	// 	return err
	// }

	actions := []images.Action{
		{Op: &images.SetHostnameCommand{Hostname: hostname}},
		// NB: some of the cilium tests expect a /usr/bin/cp
		{Op: &images.RunCommand{Cmd: "cp /bin/cp /usr/bin/cp"}},
	}
	actions = append(actions, fsActions...)
	// actions = append(actions, testerActions...)

	if !rcnf.DisableNetwork {
		netActions, err :=  ConfigNetworkD(tmpDir)
		if err != nil {
			return fmt.Errorf("config networkD: %w", err)
		}

		actions = append(actions, netActions...)
	}

	cnf := images.ImagesConf{
		Dir: imagesDir,
		// TODO: might be useful to modify the images builder so that
		// we can build this image using qemu-img -b
		Images: []images.ImgConf{{
			Name:    rcnf.TestImage,
			Parent:  baseImage,
			Actions: actions,
		}},
	}

	forest, err := images.NewImageForest(&cnf, false)
	if err != nil {
		log.Fatal(err)
	}

	res := forest.BuildAllImages(&images.BuildConf{
		Log:          log,
		DryRun:       false,
		ForceRebuild: !rcnf.DontRebuildImage,
		MergeSteps:   true,
	})

	return res.Err()
}

const primaryNetworkIface = "ens2"

func ConfigNetworkD(tmpDir string) ([]images.Action, error) {
	netdDHCPConf := `[Match]
Name=%s

[Network]
DHCP=yes
`

	tmpConfFile := filepath.Join(tmpDir, "20-primary.network")
	if err := os.WriteFile(tmpConfFile, []byte(fmt.Sprintf(netdDHCPConf, primaryNetworkIface)), 0722); err != nil {
		return nil, err
	}

	return  []images.Action{
		{Op: &images.CopyInCommand{LocalPath: tmpConfFile, RemoteDir: "/etc/systemd/network/"}},
		{Op: &images.ChmodCommand{File: "/etc/systemd/network/20-primary.network", Permissions: "0644"}},
	}, nil
}
