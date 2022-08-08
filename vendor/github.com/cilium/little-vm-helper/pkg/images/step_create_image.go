package images

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/cilium/little-vm-helper/pkg/logcmd"
	"github.com/hashicorp/packer-plugin-sdk/multistep"
)

var (
	// DelImageIfExists: if set to true, image will be deleted at Cleanup() by the CreateImage step
	DelImageIfExists = "DelImageIfExist"
)

// Approach for creating images:
// - Base (root) images are build using mmdebstrap and copying files using guestfish.
// - Non-root images are build using virt-customize, by copying the parent.
// - All images use the raw format (not qcow2)
// - Images are read-only. Users can use them to create other images (by copying or via qcow2)
//
// Alternative options I considred and may be useful for future reference:
//  - using qemu-nbd+chroot, would probably be a faster way to do this, but it requires root.
//  - using either debootstrap, or multistrap (with fakeroot and fakechroot) instead of mmdebstrap.
//    The latter seems faster, so I thought I'd use it. If something breaks, we can always go another
//    route.
//  - using the go bindings for libguestfs (https://libguestfs.org/guestfs-golang.3.html). Using the
//    CLI seemed simpler.
//  - having bootable images. I don't think we need this since we can specify --kernel and friends
//    in qemu.
//  - having the images in qcow2 so that we save some space. I think the sparsity of the files is
//    enough, so decided to keep things simple. Note that we can use virt-sparsify if we want to (e.g.,
//    when downloading images).

// CreateImage is a step for creating an image. Its cleanup will delete the image if DelImageIfExists is set.

type CreateImage struct {
	*StepConf
	bootable bool
}

func NewCreateImage(cnf *StepConf) *CreateImage {
	return &CreateImage{
		StepConf: cnf,
		// NB(kkourt): for now all the images we create are bootable because we can always
		// boot them by directly specifing -kernel in qemu. Kept this, however, in case at
		// some point we want to change it. Note, also, that because all images are
		// bootable, it is sufficient to do create root bootable images.
		bootable: true,
	}
}

var extLinuxConf = `
default linux
timeout 0

label linux
kernel /vmlinuz
append initrd=initrd.img root=/dev/sda rw console=ttyS0
`

func (s *CreateImage) makeRootImage(ctx context.Context) error {
	imgFname := filepath.Join(s.imagesDir, s.imgCnf.Name)
	tarFname := path.Join(s.imagesDir, fmt.Sprintf("%s.tar", s.imgCnf.Name))
	// build package list: add a kernel if building a bootable image
	packages := make([]string, 0, len(s.imgCnf.Packages)+1)
	if s.bootable {
		packages = append(packages, "linux-image-amd64")
	}
	packages = append(packages, s.imgCnf.Packages...)

	cmd := exec.CommandContext(ctx, Mmdebstrap,
		"sid",
		"--include", strings.Join(packages, ","),
		tarFname,
	)
	err := logcmd.RunAndLogCommand(cmd, s.log)
	if err != nil {
		return err
	}
	defer func() {
		err := os.Remove(tarFname)
		if err != nil {
			s.log.WithError(err).Info("failed to remove tarfile")
		}
	}()

	// example: guestfish -N foo.img=disk:8G -- mkfs ext4 /dev/sda : mount /dev/sda / : tar-in /tmp/foo.tar /
	if s.bootable {
		dirname, err := os.MkdirTemp("", "extlinux-")
		if err != nil {
			return err
		}
		defer func() {
			os.RemoveAll(dirname)
		}()
		fname := filepath.Join(dirname, "extlinux.conf")
		if err := os.WriteFile(fname, []byte(extLinuxConf), 0722); err != nil {
			return err
		}

		cmd = exec.CommandContext(ctx, GuestFish,
			"-N", fmt.Sprintf("%s=disk:%s", imgFname, DefaultImageSize),
			"--",
			"part-disk", "/dev/sda", "mbr",
			":",
			"part-set-bootable", "/dev/sda", "1", "true",
			":",
			"mkfs", "ext4", "/dev/sda",
			":",
			"mount", "/dev/sda", "/",
			":",
			"tar-in", tarFname, "/",
			":",
			"extlinux", "/",
			":",
			"copy-in", fname, "/",
		)
	} else {
		cmd = exec.CommandContext(ctx, GuestFish,
			"-N", fmt.Sprintf("%s=disk:%s", imgFname, DefaultImageSize),
			"--",
			"mkfs", "ext4", "/dev/sda",
			":",
			"mount", "/dev/sda", "/",
			":",
			"tar-in", tarFname, "/",
		)
	}

	if err := logcmd.RunAndLogCommand(cmd, s.log); err != nil {
		return err
	}

	if imageFormatFromFname(imgFname) == "qcow2" {
		tmpImage := fmt.Sprintf("%s.img", imgFname)
		if err := os.Rename(imgFname, tmpImage); err != nil {
			return err
		}
		defer os.Remove(tmpImage)
		cmd := exec.CommandContext(ctx, QemuImg, "convert", "-f", "raw", "-O", "qcow2", tmpImage, imgFname)
		return logcmd.RunAndLogCommand(cmd, s.log)
	}

	return nil

}

func (s *CreateImage) makeDerivedImage(ctx context.Context) error {
	parFname := filepath.Join(s.imagesDir, s.imgCnf.Parent)
	imgFname := filepath.Join(s.imagesDir, s.imgCnf.Name)

	parFmt := imageFormatFromFname(parFname)
	imgFmt := imageFormatFromFname(imgFname)

	cmd := exec.CommandContext(ctx, QemuImg, "convert", "-f", parFmt, "-O", imgFmt, parFname, imgFname)
	err := logcmd.RunAndLogCommand(cmd, s.log)
	if err != nil {
		return err
	}

	if len(s.imgCnf.Packages) > 0 {
		cmd = exec.CommandContext(ctx, VirtCustomize,
			"-a", imgFname,
			"--install", strings.Join(s.imgCnf.Packages, ","),
		)
		return logcmd.RunAndLogCommand(cmd, s.log)
	}

	return nil
}

func (s *CreateImage) Run(ctx context.Context, b multistep.StateBag) multistep.StepAction {

	var err error
	if s.imgCnf.Parent == "" {
		err = s.makeRootImage(ctx)
	} else {
		err = s.makeDerivedImage(ctx)
	}

	if err != nil {
		s.log.WithField("image", s.imgCnf.Name).WithError(err).Error("error buiding image")
		b.Put("err", err)
		return multistep.ActionHalt
	}
	return multistep.ActionContinue

}

func (s *CreateImage) Cleanup(b multistep.StateBag) {
}
