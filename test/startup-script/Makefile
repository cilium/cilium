TAG=v2
IMAGE=docker.io/cilium/startup-script

.PHONY: build push

build:
	docker build --pull -t $(IMAGE):$(TAG) .

push: build
	docker push $(IMAGE):$(TAG)
