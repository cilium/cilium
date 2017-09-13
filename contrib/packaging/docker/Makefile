include ../../../Makefile.defs

# Generate random string to append to directory so we can build multiple Docker images concurrently in Jenkins.
BUILDDIR := "$(CURDIR)/stage/cilium-$(VERSION)-$(k8s_version)"

docker-image-prod: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	cp -v ../../../Dockerfile $(BUILDDIR)
	find $(BUILDDIR)/ -name ".*" -prune ! -name ".git" -exec $(RM) -rf {} \;
	docker build -t "cilium:$(DOCKER_IMAGE_TAG)" $(BUILDDIR)

docker-image-dev: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	cp -v ../../../Dockerfile.dev $(BUILDDIR)/Dockerfile
	find $(BUILDDIR) -name ".*" -prune ! -name ".git" -exec $(RM) -rf {} \;
	docker build -q -t "cilium:$(DOCKER_IMAGE_TAG)" $(BUILDDIR)
	make clean

docker-image-dependencies: clean
	mkdir -p $(BUILDDIR)
	@$(CURDIR)/../cp-dirs.sh $(BUILDDIR)
	cp -v ../../../Dockerfile.deps $(BUILDDIR)/Dockerfile
	find $(BUILDDIR) -name ".*" -prune ! -name ".git" -exec $(RM) -rf {} \;
	docker build -q -t "cilium:dependencies" $(BUILDDIR)
clean:
	ls -d ./$(BUILDDIR) | grep -vE "Makefile|clang-3.8.1.key|build_dockerfile.sh" | xargs $(RM) -rf

.PHONY: clean build force
force :;
