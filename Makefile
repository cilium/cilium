all:
	$(MAKE) -C docker-plugin
	$(MAKE) -C common/bpf

tests:
	$(MAKE) -C cilium-net-daemon tests
	$(MAKE) -C common tests
	$(MAKE) -C docker-plugin tests
	$(MAKE) -C integration tests

run-docker-plugin:
	$(MAKE) -C docker-plugin run

run-cilium-daemon:
	$(MAKE) -C cilium-net-daemon run

clean:
	$(MAKE) -C docker-plugin clean
	$(MAKE) -C common/bpf clean
