.PHONY: bin
bin: VERSION := $(shell git log --oneline -- . | wc -l | tr -d ' ')
bin: BINNAME :=
bin:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o dist/$(BINNAME)

.PHONY: dist
dist:
	mkdir -p dist
	make build GOOS=linux GOARCH=amd64
	make build GOOS=linux GOARCH=arm64
	make build GOOS=darwin GOARCH=amd64
	make build GOOS=darwin GOARCH=arm64
	make build GOOS=windows GOARCH=amd64 EXT=.exe

.PHONY: build
build: EXT :=
build:
	make bin BINNAME=gotlsproxy_$(GOOS)_$(GOARCH)$(EXT)

clean:
	rm -fr dist
