all:
	$(MAKE) -C docker-plugin
	$(MAKE) -C common/bpf

tests:
	$(MAKE) -C cilium-net-daemon
	$(MAKE) -C common
	$(MAKE) -C docker-plugin
	$(MAKE) -C integration

run-docker-plugin:
	$(MAKE) -C docker-plugin run

clean:
	$(MAKE) -C docker-plugin clean
	$(MAKE) -C common/bpf clean
