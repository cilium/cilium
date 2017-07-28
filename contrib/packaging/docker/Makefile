include ../../../Makefile.defs

BUILDDIR := "$(CURDIR)/stage/cilium-$(VERSION)"

docker-image-prod: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	./build_dockerfile.sh build_docker_prod
	find $(BUILDDIR) -name ".*" -prune ! -name ".git"  -exec $(RM) -rf {} \;
	docker build -t "cilium:${DOCKER_IMAGE_TAG}" $(BUILDDIR)

docker-image-dev: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)../cp-dirs.sh $(BUILDDIR)
	./build_dockerfile.sh build_docker_dev
	find $(BUILDDIR) -name ".*" -prune ! name ".git" -exec $(RM) -rf{} \;
	docker build -t "cilium:$(DOCKER_IMAGE_TAG)" $(BUILDDIR)

clean:
	ls -d ./* | grep -vE "Makefile|clang-3.8.1.key" | xargs $(RM) -rf

.PHONY: clean build force
force :;
