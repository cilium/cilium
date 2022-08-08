package lvhrunner

import "fmt"

type QemuFS interface {
	QemuArgs() []string
	FStabEntry() string
	VMMountpoint() string
}

type VirtIOFilesystem struct {
	ID      string
	Hostdir string
	VMdir   string
}

func (fs *VirtIOFilesystem) VMMountpoint() string {
	return fs.VMdir
}

func (fs *VirtIOFilesystem) QemuArgs() []string {
	fsId := fmt.Sprintf("%s_id", fs.ID)
	tag := fmt.Sprintf("%s_tag", fs.ID)
	return []string{
		"-fsdev", fmt.Sprintf("local,id=%s,path=%s,security_model=none", fsId, fs.Hostdir),
		"-device", fmt.Sprintf("virtio-9p-pci,fsdev=%s,mount_tag=%s", fsId, tag),
	}
}

func (fs *VirtIOFilesystem) FStabEntry() string {
	tag := fmt.Sprintf("%s_tag", fs.ID)
	return fmt.Sprintf("%s\t%s\t9p\ttrans=virtio,rw\t0\t0\n", tag, fs.VMdir)
}
