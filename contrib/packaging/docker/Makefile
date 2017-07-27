include ../../../Makefile.defs

BUILDDIR := "$(CURDIR)/stage/cilium-$(VERSION)"

build: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	#cp -v ../../../Dockerfile.dependencies $(BUILDDIR)/Dockerfile
	cp -v ../../../Dockerfile $(BUILDDIR)
	find $(BUILDDIR) -name ".*" -prune ! -name ".git"  -exec $(RM) -rf {} \;
	docker build -t "cilium:dependencies" $(BUILDDIR)

clean:
	ls -d ./* | grep -vE "Makefile|clang-3.8.1.key" | xargs $(RM) -rf

.PHONY: clean build force
force :;
