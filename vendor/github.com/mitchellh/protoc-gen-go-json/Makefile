.PHONY: proto
proto:
	mkdir -p build
	go build -o build/protoc-gen-go-json .
	export PATH=$(CURDIR)/build/:$$PATH && \
	    cd e2e && protoc --go_out=. --go-json_out=logtostderr=true,v=10:. *.proto
