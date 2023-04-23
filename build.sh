#!/bin/bash

export PATH="$PATH:$(go env GOPATH)/bin"
protoc -I proto/ --go_out=internal/proto --go_opt=paths=source_relative --go-grpc_out=internal/proto --go-grpc_opt=paths=source_relative proto/script_verifier.proto
go build -o ./bin/server ./cmd/server/main.go