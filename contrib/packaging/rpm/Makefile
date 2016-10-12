include ../../../Makefile.defs

BUILDDIR := "$(CURDIR)/cilium-$(VERSION)"

build: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	find $(BUILDDIR) -name ".*" -exec rm -rf {} \;
	cp $(CURDIR)/cfg/* $(BUILDDIR)
	$(MAKE) -C $(BUILDDIR) clean
	tar -czf cilium-$(VERSION).tar.gz cilium-$(VERSION)
	mv cilium-$(VERSION).tar.gz cilium-$(VERSION)/
	docker build -t cilium:cilium-bin-rpm-$(VERSION) $(BUILDDIR)
	docker run --rm cilium:cilium-bin-rpm-$(VERSION) bash -c \
	  'tar -c cilium-$(VERSION)*.rpm x86_64/cilium-$(VERSION)*.rpm' | tar -xvC .

clean:
	ls -d ./* | grep -vE Makefile\|cfg | xargs rm -rf

.PHONY: force build clean
force :;

