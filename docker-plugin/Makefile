all: tests

tests:
	godep go fmt ./...
	godep go test ./...

cilium-docker:
	godep go build -o cilium-docker

run:
	./cilium-docker -d -n beef::1:0:0

clean:
	rm -f cilium-docker
