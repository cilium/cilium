image_version:="0.0.18"

build-all: clean validate
	packer build ubuntu-1404.json

validate:
	packer validate ubuntu-1404.json
	packer validate ubuntu-1404-atlas.json

build-libvirt: clean validate
	packer build -only=libvirt ubuntu-1404.json
	./scripts/optimize_libvirt_box.sh

build-vmware: clean validate
	packer build -only=vmware ubuntu-1404.json

build-vbox: clean validate
	packer build -only=virtualbox ubuntu-1404.json

clean:
	rm -Rf output-* *.box tmp

distclean:
	rm -Rf output-* *.box packer_cache tmp

uninstall_libvirt:
	vagrant destroy
	vagrant box remove noironetworks/net-next
	sudo virsh vol-delete --pool default "noironetworks-VAGRANTSLASH-net-next_vagrant_box_image_${image_version}.img"
	-service libvirt-bin restart
	-service libvirtd restart
	rm Vagrantfile

uninstall_vbox:
	vagrant destroy
	vagrant box remove noironetworks/net-next
	rm Vagrantfile

upload:
	packer push -name noironetworks/net-next ubuntu-1404-atlas.json

install_libvirt:
	vagrant box add --force noironetworks/net-next ubuntu-1404-libvirt.box
	cp Vagrantfile.sample  Vagrantfile
	vagrant up --provider=libvirt

install_vbox:
	vagrant box add --force noironetworks/net-next ubuntu-1404-libvirt.box
	cp Vagrantfile.sample  Vagrantfile
	vagrant up --provider=virtualbox
