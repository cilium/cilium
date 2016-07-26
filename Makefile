include Makefile.defs

SUBDIRS = plugins cilium bpf common
SUBDIRSLIB = daemon integration

all: $(SUBDIRS)

$(SUBDIRS): force
	@ $(MAKE) -C $@ all

tests: force
	for i in $(SUBDIRS); do $(MAKE) -C $$i -B tests; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i -B tests; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i clean; done

install:
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/lib
	$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)/cilium/githooks
	for i in $(SUBDIRS); do $(MAKE) -C $$i install; done
	for i in $(SUBDIRSLIB); do $(MAKE) -C $$i install; done

docker-image:
	@./contrib/docker/cp-dirs.sh
	$(MAKE) -C ./contrib/docker clean
	docker build -t "noironetworks:cilium-ubuntu-15-10" ./contrib/docker/
	ls -d ./contrib/docker/* | grep -v cp-dirs.sh | xargs rm -r

runtime-tests:
	$(MAKE) -C tests runtime-tests

.PHONY: force
force :;
