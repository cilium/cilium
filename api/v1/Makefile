include ../../images/hubble-proto/Makefile.defs

.PHONY: proto
proto:
	docker container run --rm \
		-u $(shell id -u):$(shell id -g) \
		--volume $(CURDIR):/source \
		cilium/hubble-proto:${version}
