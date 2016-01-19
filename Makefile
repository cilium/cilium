all:
	$(MAKE) -C docker-plugin
	$(MAKE) -C common/bpf

run-docker-plugin:
	$(MAKE) -C docker-plugin run

clean:
	$(MAKE) -C docker-plugin clean
	$(MAKE) -C common/bpf clean
