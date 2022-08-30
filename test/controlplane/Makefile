.PHONY: all test update-golden

all: test

test:
	go test .

update-golden:
	go test . -test.v -update

pre-pull-kind-images:
	bash ./k8s_versions.sh --pre-pull-images

update-k8s-versions:
	# Update kind-config with the versions stored in k8s_versions.txt
	$(shell bash ./k8s_versions.sh --update-kind-config)

generate-input-files: pre-pull-kind-images update-k8s-versions
	find . -name generate.sh -exec {} \;
