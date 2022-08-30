.PHONY: all test update-golden

all: test

test:
	go test .

update-golden:
	go test . -test.v -update

pre-pull-kind-images:
	bash ./k8s_versions.sh --pre-pull-images
