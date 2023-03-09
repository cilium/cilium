#!/bin/bash -ex

# on macs, you may need to:
# export GOBUILDFLAG=-ldflags -linkmode=external

echo "Running unit tests"
go test -race

echo "Testing against postgres"
export GORP_TEST_DSN="host=postgres user=gorptest password=gorptest dbname=gorptest sslmode=disable"
export GORP_TEST_DIALECT=postgres
go test -tags integration $GOBUILDFLAG $@ .

echo "Testing against sqlite"
export GORP_TEST_DSN=/tmp/gorptest.bin
export GORP_TEST_DIALECT=sqlite
go test -tags integration $GOBUILDFLAG $@ .
rm -f /tmp/gorptest.bin

echo "Testing against mysql"
export GORP_TEST_DSN="gorptest:gorptest@tcp(mysql)/gorptest"
export GORP_TEST_DIALECT=mysql
go test -tags integration $GOBUILDFLAG $@ .
