#!/bin/bash -ex

# on macs, you may need to:
# export GOBUILDFLAG=-ldflags -linkmode=external

coveralls_testflags="-v -covermode=count -coverprofile=coverage.out"

echo "Running unit tests"
go test -race

echo "Testing against mysql"
export GORP_TEST_DSN=gorptest/gorptest/gorptest
export GORP_TEST_DIALECT=mysql
go test -tags integration $coveralls_testflags $GOBUILDFLAG $@ .

echo "Testing against gomysql"
export GORP_TEST_DSN=gorptest:gorptest@/gorptest
export GORP_TEST_DIALECT=gomysql
go test -tags integration $coveralls_testflags $GOBUILDFLAG $@ .

echo "Testing against postgres"
export GORP_TEST_DSN="user=gorptest password=gorptest dbname=gorptest sslmode=disable"
export GORP_TEST_DIALECT=postgres
go test -tags integration $coveralls_testflags $GOBUILDFLAG $@ .

echo "Testing against sqlite"
export GORP_TEST_DSN=/tmp/gorptest.bin
export GORP_TEST_DIALECT=sqlite
go test -tags integration $coveralls_testflags $GOBUILDFLAG $@ .
rm -f /tmp/gorptest.bin

case $(go version) in
  *go1.4*)
    if [ "$(type -p goveralls)" != "" ]; then
	  goveralls -covermode=count -coverprofile=coverage.out -service=travis-ci
    elif [ -x $HOME/gopath/bin/goveralls ]; then
	  $HOME/gopath/bin/goveralls -covermode=count -coverprofile=coverage.out -service=travis-ci
    fi
  ;;
  *) ;;
esac
