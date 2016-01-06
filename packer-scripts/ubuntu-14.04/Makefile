build-all: clean validate
	packer build ubuntu-1404.json

validate:
	packer validate ubuntu-1404.json

build-libvirt: clean validate
	packer build -only=libvirt ubuntu-1404.json
	./scripts/optimize_libvirt_box.sh

build-vmware: clean validate
	packer build -only=vmware ubuntu-1404.json

clean:
	rm -Rf output-*
	rm -Rf *.box
	rm -Rf packer_cache

uninstall:
	vagrant destroy
	vagrant box remove cilium-net-next
	sudo rm /var/lib/libvirt/images/cilium-net-next_vagrant_box_image_0.img
	-service libvirt-bin restart
	-service libvirtd restart
	rm Vagrantfile

upload:
	export ATLAS_TOKEN="TaYfAGybFnRBcQ.atlasv1.VBoRms3WdhuyrzOiLSVXoJ23J65R4EIjBbcjCJyCeqm2V8pwWzLBr641agFzj5CpYXk"
	packer push -name noironetworks/cilium-net-next ubuntu-1404-atlas.json

install:
	vagrant box add --force cilium-net-next ubuntu-1404-libvirt.box
	cp Vagrantfile.sample  Vagrantfile
	vagrant up --provider=libvirt
