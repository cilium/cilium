all: tests

tests:
	-docker run -d \
           --name "cilium-consul-container-test" \
           -p 8500:8500 \
           progrium/consul \
           -server -bootstrap-expect 1
	godep go fmt ./...
	-godep go test ./...
	docker rm -f "cilium-consul-container-test"
