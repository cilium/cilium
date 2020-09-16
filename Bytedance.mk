SHELL := /bin/bash

VERSION := $(shell git describe --tags)
DEV_IMAGE_HUB := cloud-sys.byted.org:5000/oort/
IMAGE_HUB := oort-hub.byted.org/public/alto
DOCKER_IMAGE := cilium/cilium:$(VERSION)
DOCKER_DEV_IMAGE := cilium/cilium-dev:latest
DOCKER_CMD := $(shell if docker ps &>/dev/null; then echo docker; else echo sudo docker; fi)
K8S_TOKEN ?= $(if $(K8S_TOKEN_BASE64),$(shell echo $(K8S_TOKEN_BASE64) | base64 -d))
KUBECTL := ./bin/kubectl --insecure-skip-tls-verify=true $(if $(K8S_SERVER), --server=$(K8S_SERVER)) $(if $(K8S_TOKEN), --token=$(K8S_TOKEN))

.PHONY: docker-dev deploy-dev docker

all:
	@ echo "Usage: make docker|docker-dev|deploy-dev"

deploy-dev: docker-dev
	$(KUBECTL) apply -f deploy/cilium-dev.yml
	$(KUBECTL) -n kube-system delete pod -l k8s-app=cilium
	for i in {1..60}; do sleep 1; if test "$$($(KUBECTL) -n kube-system get pod -l k8s-app=cilium -o 'jsonpath={.items[0].status.phase}')" == "Running"; then exit 0; fi; done; echo "cilium not running"; exit 1
	for i in {1..60}; do sleep 1; if test "$$(/usr/bin/curl -so /dev/null -w %{http_code} http://10.17.127.61/)" == "200"; then exit 0; fi; done; echo "external vip not working"; exit 1

docker: IMAGE = $(DOCKER_IMAGE) ACTION = docker-image
docker-dev: IMAGE = $(DOCKER_DEV_IMAGE) ACTION = dev-docker-image

docker-dev docker-test:
	make dev-docker-image
	$(DOCKER_CMD) tag  $(DOCKER_DEV_IMAGE) $(DEV_IMAGE_HUB)$(DOCKER_DEV_IMAGE)
	$(DOCKER_CMD) push $(DEV_IMAGE_HUB)$(DOCKER_DEV_IMAGE)

docker:
	DOCKER_IMAGE_TAG=$(VERSION) make docker-image
	$(DOCKER_CMD) tag  $(DOCKER_IMAGE) $(IMAGE_HUB)/cilium:$(VERSION)
	$(DOCKER_CMD) push $(IMAGE_HUB)/cilium:$(VERSION)
	$(DOCKER_CMD) tag  cilium/operator:$(VERSION) $(IMAGE_HUB)/cilium-operator:$(VERSION)
	$(DOCKER_CMD) push $(IMAGE_HUB)/cilium-operator:$(VERSION)
	$(DOCKER_CMD) tag  cilium/docker-plugin:$(VERSION) $(IMAGE_HUB)/cilium-docker-plugin:$(VERSION)
	$(DOCKER_CMD) push $(IMAGE_HUB)/cilium-docker-plugin:$(VERSION)
