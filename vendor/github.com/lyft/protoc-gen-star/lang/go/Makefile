.PHONY: testdata-go-names
testdata-names: ../../bin/protoc-gen-debug # parse the proto file sets in testdata/names and renders binary CodeGeneratorRequest + official go codegen
	cd testdata/names && \
	set -e; for subdir in `find . -type d -mindepth 1 -maxdepth 1`; do \
		cd $$subdir; \
		params=`cat params`; \
		protoc -I . \
			--plugin=protoc-gen-debug=../../../../../bin/protoc-gen-debug \
			--debug_out=".:." \
			--go_out="plugins,paths=source_relative,$$params:." \
			`find . -name "*.proto"`; \
		cd -; \
	done

testdata-packages: ../../bin/protoc-gen-debug
	cd testdata/packages && \
	set -e; for subdir in `find . -type d -mindepth 1 -maxdepth 1 | grep -v targets`; do \
		cd $$subdir; \
		params=`cat params`; \
		protoc -I . -I .. \
			--plugin=protoc-gen-debug=../../../../../bin/protoc-gen-debug \
			--debug_out=".:." \
			--go_out="paths=source_relative,$$params:." \
			`find . -name "*.proto"`; \
		cd -; \
	done

testdata-outputs: ../../bin/protoc-gen-debug
	cd testdata/outputs && \
	set -e; for subdir in `find . -type d -mindepth 1 -maxdepth 1`; do \
		cd $$subdir; \
		params=`cat params`; \
		protoc -I . -I .. \
			--plugin=protoc-gen-debug=../../../../../bin/protoc-gen-debug \
			--debug_out=".:." \
			--go_out="$$params:." \
			`find . -name "*.proto"`; \
		cd -; \
	done

../../bin/protoc-gen-debug:
	cd ../.. && $(MAKE) bin/protoc-gen-debug
