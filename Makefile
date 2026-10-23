BINARY := cerberus
VERSION ?= 0.2.0
LDFLAGS := -s -w -X github.com/Baba01hacker666/cerberus/cmd.version=$(VERSION)

.PHONY: build test test-root vet clean release

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

test:
	go test -race ./...

test-root:
	sudo env PATH="$(PATH)" GOPATH="$(shell go env GOPATH)" GOCACHE="$(shell go env GOCACHE)" go test -race -v ./...

vet:
	go vet ./...

clean:
	rm -rf $(BINARY) dist

release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 .
