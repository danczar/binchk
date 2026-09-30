VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PKG     := ./cmd/binchk

.PHONY: build all darwin linux windows app icons test bench rules clean

build:            ## native build for this machine
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/binchk $(PKG)

all: darwin linux windows

darwin:           ## needs cgo (menu bar): build on a Mac
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/darwin-arm64/binchk $(PKG)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/darwin-amd64/binchk $(PKG)
	lipo -create -output dist/binchk-darwin dist/darwin-arm64/binchk dist/darwin-amd64/binchk
	codesign --force --sign - dist/binchk-darwin   # lipo invalidates per-slice signatures

linux:            ## pure Go (tray via D-Bus StatusNotifierItem)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/binchk-linux-amd64 $(PKG)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/binchk-linux-arm64 $(PKG)
	mkdir -p dist/linux
	cp assets/icon/binchk-256.png dist/linux/binchk.png
	cp scripts/binchk.desktop dist/linux/binchk.desktop

windows:          ## pure Go; -H=windowsgui hides the console; icon via cmd/binchk/rsrc_*.syso
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS) -H=windowsgui" -o dist/binchk-windows-amd64.exe $(PKG)
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS) -H=windowsgui" -o dist/binchk-windows-arm64.exe $(PKG)

app: darwin       ## macOS menu-bar .app bundle
	scripts/macos-bundle.sh dist/binchk-darwin $(VERSION)

icons:            ## re-render assets/icon and the Windows resources (.syso)
	go run ./tools/mkicon
	go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --out cmd/binchk/rsrc --arch amd64,arm64

test:
	go test -race ./...

bench:
	go test ./internal/ac ./internal/analyze -run xxx -bench . -benchtime 20x

rules:            ## re-embed internal/analyze/rules/builtin.json after editing it
	go generate ./internal/analyze

clean:
	rm -rf bin dist .preview
