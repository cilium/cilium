build-all: clean validate
	packer build ubuntu-1404.json

validate:
	packer validate ubuntu-1404.json

build-libvirt: clean validate
	packer build -only=libvirt ubuntu-1404.json

build-vmware: clean validate
	packer build -only=vmware ubuntu-1404.json

clean:
	rm -Rf output-*
	rm -Rf *.box

uninstall:
	vagrant destroy
	vagrant box remove ubuntu64
	rm /var/lib/libvirt/images/*
	service libvirt-bin restart
	rm Vagrantfile

install:
	vagrant box add ubuntu64 ubuntu-1404-libvirt.box
	vagrant init ubuntu64
	cp Vagrantfile.sample  Vagrantfile
	vagrant up --provider=libvirt
