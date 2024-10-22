#/bin/sh

set -x

# Fix up generated code.
gofix()
{
    IN=$1
    OUT=$2

    # Change types that are a nuisance to deal with in Go, use byte for
    # consistency, and produce gofmt'd output.
    sed 's/]u*int8/]byte/g' $1 | gofmt -s > $2
}

echo -e "//+build freebsd,amd64\n" > /tmp/wgamd64.go
GOARCH=amd64 go tool cgo -godefs defs.go >> /tmp/wgamd64.go

echo -e "//+build freebsd,386\n" > /tmp/wg386.go
GOARCH=386 go tool cgo -godefs defs.go >> /tmp/wg386.go

echo -e "//+build freebsd,arm64\n" > /tmp/wgarm64.go
GOARCH=arm64 go tool cgo -godefs defs.go >> /tmp/wgarm64.go

echo -e "//+build freebsd,arm\n" > /tmp/wgarm.go
GOARCH=arm go tool cgo -godefs defs.go >> /tmp/wgarm.go

gofix /tmp/wgamd64.go defs_freebsd_amd64.go
gofix /tmp/wg386.go defs_freebsd_386.go
gofix /tmp/wgarm64.go defs_freebsd_arm64.go
gofix /tmp/wgarm.go defs_freebsd_arm.go

rm -rf _obj/ /tmp/wg*.go
