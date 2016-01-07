deps:
	godep get
	cd ${GOPATH}/src/k8s.io/kubernetes/
	godep restore

all:
	go build -o cilium-docker

run:
	./cilium-docker -d -n beef::1:0:0:0
