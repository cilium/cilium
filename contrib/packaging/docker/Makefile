include ../../../Makefile.defs

BUILDDIR := "$(CURDIR)/stage/cilium-$(VERSION)"

docker-image-prod: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	cp -v ../../../Dockerfile $(BUILDDIR)
	find $(BUILDDIR) -name ".*" -prune ! -name ".git" -exec $(RM) -rf {} \;
	docker build -t "cilium:$(DOCKER_IMAGE_TAG)" $(BUILDDIR)

docker-image-dev: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	cp -v ../../../Dockerfile.dev $(BUILDDIR)/Dockerfile
	find $(BUILDDIR) -name ".*" -prune ! -name ".git" -exec $(RM) -rf {} \;
	docker build -q -t "cilium:$(DOCKER_IMAGE_TAG)" $(BUILDDIR)

docker-image-dependencies: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	cp -v ../../../Dockerfile.deps $(BUILDDIR)/Dockerfile
	find $(BUILDDIR) -name ".*" -prune ! -name ".git" -exec $(RM) -rf {} \;
	docker build -q -t "cilium:dependencies" $(BUILDDIR)

clean:
	ls -d ./* | grep -vE "Makefile|clang-3.8.1.key|build_dockerfile.sh" | xargs $(RM) -rf

dockerfiles: clean
	./build_dockerfile.sh build_dockerfile_dev
	mv ./Dockerfile ../../../Dockerfile.dev
	./build_dockerfile.sh build_dockerfile_dependencies
	mv ./Dockerfile ../../../Dockerfile.deps
	./build_dockerfile.sh build_dockerfile_prod
	mv ./Dockerfile ../../../Dockerfile

.PHONY: clean build force
force :;
