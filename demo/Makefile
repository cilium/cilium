.PHONY: all build test run statedb health add delete maps

all: build test
	@echo
	@echo "See 'Makefile' for more targets"
	@echo "Type 'make run' to run the app"

build:
	go build .

test:
	go test ./...

run: build
	sudo ./demo --k8s-kubeconfig-path ~/.kube/config

statedb:
	curl -s localhost:8080/statedb

health:
	curl -s localhost:8080/health | jq .

add:
	curl localhost:8080/services -d \
        	'{"Name": "hello", "ServiceType": "NodePort", "ClusterIP": "1.2.3.4", "Port": 1234, "Protocol": "TCP"}'
	curl localhost:8080/endpoints -d \
		'{"Service": "hello", "Addrs": ["2.3.4.5"], "Ports": [{"Port": 5000, "Protocol": "TCP"}], "Protocol": "TCP"}'

delete:
	curl -XDELETE localhost:8080/services/hello
	curl -XDELETE localhost:8080/endpoints/hello

maps:
	sudo bpftool map dump name frontends
	sudo bpftool map dump name backends


