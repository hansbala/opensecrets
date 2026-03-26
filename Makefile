BINDIR ?= /usr/local/bin
BIN_NAME := opensecrets
GO_FLAGS := CGO_ENABLED=0

.PHONY: build
build:
	@$(GO_FLAGS) go build -o $(BIN_NAME) main.go

.PHONY: link
link: build
	@ln -sf "$(CURDIR)/$(BIN_NAME)" "$(BINDIR)/$(BIN_NAME)"

.PHONY: fmt
fmt:
	@gofmt -w main.go
