include ../../images/hubble-proto/Makefile.defs

.PHONY: proto
proto:
	docker container run --rm \
		--volume $(CURDIR):/source \
		cilium/hubble-proto:${version}
