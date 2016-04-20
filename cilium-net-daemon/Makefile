include ../Makefile.defs

TARGET=cilium-net-daemon

all: $(TARGET)

tests:
	-docker run -d \
           --name "cilium-consul-test-container" \
           -p 8501:8500 \
           progrium/consul \
           -server -bootstrap-expect 1
	godep go fmt ./...
	-godep go test ./...
	docker rm -f "cilium-consul-test-container"

runtime-tests:

run:

clean:
	rm -f $(TARGET)

$(TARGET):

install:
