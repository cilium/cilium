include ../Makefile.defs

TARGET=cilium-net-daemon

all: $(TARGET)

tests:
	-docker rm -f "cilium-consul-test-container"
	-docker run -d \
           --name "cilium-consul-test-container" \
           -p 8501:8500 \
           -e 'CONSUL_LOCAL_CONFIG={"skip_leave_on_interrupt": true}' \
           consul:v0.6.4 \
           agent -client=0.0.0.0 -server -bootstrap-expect 1
	go fmt ./...
	sudo -E env "PATH=${PATH}" go test -timeout 30s ./...
	-rmdir ./daemon/1 ./daemon/1_backup
	docker rm -f "cilium-consul-test-container"

runtime-tests:

run:

clean:
	rm -f $(TARGET)

$(TARGET):

install:
	groupadd -f cilium
	cp -r ui/. $(DESTDIR)$(RUNDIR)/cilium/static
