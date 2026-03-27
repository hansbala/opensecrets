BINDIR ?= /usr/local/bin
BIN_NAME := opensecrets
VERSION ?= $(shell cat VERSION)
GO_FLAGS := CGO_ENABLED=0

.PHONY: build
build:
	@$(GO_FLAGS) go build -ldflags "-X main.cVersion=$(VERSION)" -o $(BIN_NAME) main.go

.PHONY: link
link: build
	@ln -sf "$(CURDIR)/$(BIN_NAME)" "$(BINDIR)/$(BIN_NAME)"

.PHONY: fmt
fmt:
	@gofmt -w main.go main_test.go pkg/*.go

.PHONY: test
test:
	@$(GO_FLAGS) go test ./...
