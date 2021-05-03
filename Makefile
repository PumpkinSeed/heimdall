GOFILES := $(shell find . -name "*.go" -type f ! -path "./vendor/*")
GOFMT ?= gofmt -s
PACKAGES = $(shell go list ./... | grep -v /vendor/)

proto:
	protoc --go_out=. --go-grpc_out=. pkg/structs/*.proto

.PHONY: all test
all: heimdall_darwin_amd64 heimdall_windows_amd64 heimdall_linux_amd64 heimdall_linux_arm64

heimdall_darwin_amd64:
	env GOOS=darwin GOARCH=amd64 go build -o heimdall_darwin_amd64 main.go

heimdall_windows_amd64:
	env GOOS=windows GOARCH=amd64 go build -o heimdall_windows_amd64.exe main.go

heimdall_linux_amd64:
	env GOOS=linux GOARCH=amd64 go build -o heimdall_linux_amd64 main.go

heimdall_linux_arm64:
	env GOOS=linux GOARCH=arm64 go build -o heimdall_linux_arm64 main.go

clean:
	rm -rf heimdall*

fmt:
	@$(GOFMT) -w ${GOFILES}

test:
	@go test -v -coverprofile cover.out ${PACKAGES}