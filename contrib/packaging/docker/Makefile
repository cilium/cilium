include ../../../Makefile.defs

BUILDDIR := "$(CURDIR)/cilium-$(VERSION)"

build: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	cp -v ../../../Dockerfile $(BUILDDIR)
	find $(BUILDDIR) -name ".*" -exec rm -rf {} \;
	$(MAKE) -C $(BUILDDIR) clean
	docker build -t "cilium:cilium-ubuntu-16-04" $(BUILDDIR)

clean:
	ls -d ./* | grep -vE Makefile | xargs rm -rf

.PHONY: clean build force
force :;
