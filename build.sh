#!/bin/bash
#go build -ldflags="-s -w" -o libeacct.so  -buildmode=c-shared eacct.go
go build -o libeacct.so  -buildmode=c-shared eacct.go

