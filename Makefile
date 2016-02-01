all:
	$(MAKE) -C docker-plugin
	$(MAKE) -C kubernetes-cni
	$(MAKE) -C common/bpf
	$(MAKE) -C cilium-net-daemon

tests:
	$(MAKE) -C cilium-net-daemon tests
	$(MAKE) -C common tests
	$(MAKE) -C docker-plugin tests
	$(MAKE) -C kubernetes-cni tests
	$(MAKE) -C integration tests

run-docker-plugin:
	$(MAKE) -C docker-plugin run

run-cilium-daemon:
	$(MAKE) -C cilium-net-daemon run

clean:
	$(MAKE) -C docker-plugin clean
	$(MAKE) -C kubernetes-cni clean
	$(MAKE) -C common/bpf clean
	$(MAKE) -C cilium-net-daemon clean
