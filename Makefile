VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PKG     := ./cmd/binchk

# Oldest macOS the release supports. Go 1.27 itself needs macOS 13; without an
# explicit target clang stamps the build host's version into LC_BUILD_VERSION
# and LaunchServices refuses the app on anything older. The CGO_* flags are
# needed too, because MACOSX_DEPLOYMENT_TARGET alone isn't part of go's build
# cache key. Bump together with go.mod.
MACOS_MIN  := 13.0
DARWIN_ENV := MACOSX_DEPLOYMENT_TARGET=$(MACOS_MIN) \
	CGO_CFLAGS="-O2 -g -mmacosx-version-min=$(MACOS_MIN)" \
	CGO_LDFLAGS="-mmacosx-version-min=$(MACOS_MIN)"

REL := dist/release

.PHONY: build all darwin linux windows app release icons test bench rules clean

build:            ## native build for this machine
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/binchk $(PKG)

all: darwin linux windows

darwin:           ## needs cgo (menu bar): build on a Mac
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(DARWIN_ENV) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/darwin-arm64/binchk $(PKG)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(DARWIN_ENV) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/darwin-amd64/binchk $(PKG)
	lipo -create -output dist/binchk-darwin dist/darwin-arm64/binchk dist/darwin-amd64/binchk
	codesign --force --sign - dist/binchk-darwin   # lipo invalidates per-slice signatures
	for a in arm64 x86_64; do \
		otool -arch $$a -l dist/binchk-darwin | awk '/ minos /{print $$2}' | grep -qx '$(MACOS_MIN)' \
			|| { echo "darwin $$a: minos is not $(MACOS_MIN)" >&2; exit 1; }; \
	done

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
	MACOS_MIN=$(MACOS_MIN) scripts/macos-bundle.sh dist/binchk-darwin $(VERSION)

# Release assets in $(REL); build on a Mac, then upload by hand. Timestamps
# come from the last commit and owners are zeroed so reruns are byte-identical.
# The macOS zip must not carry ._ AppleDouble entries (xattrs such as
# com.apple.provenance): unzip writes them into the sealed bundle and breaks
# its signature.
release: app linux windows
	rm -rf $(REL)
	mkdir -p $(REL)/stage
	set -eu; export TZ=UTC0 COPYFILE_DISABLE=1; \
	stamp=$$(git log -1 --format=%cd --date=format-local:%Y%m%d%H%M.%S); \
	find dist/binchk.app -exec touch -h -t $$stamp {} +; \
	codesign --verify --deep --strict dist/binchk.app; \
	(cd dist && ditto -c -k --norsrc --noextattr --noqtn --noacl --keepParent \
		binchk.app ../$(REL)/binchk-$(VERSION)-macos.zip); \
	for a in amd64 arm64; do \
		d=binchk-$(VERSION)-linux-$$a; mkdir $(REL)/stage/$$d; \
		install -m 755 dist/binchk-linux-$$a $(REL)/stage/$$d/binchk; \
		install -m 644 dist/linux/binchk.png dist/linux/binchk.desktop README.md LICENSE NOTICE $(REL)/stage/$$d/; \
		touch -t $$stamp $(REL)/stage/$$d $(REL)/stage/$$d/*; \
		tar -c -n -f - -C $(REL)/stage --format ustar --uid 0 --gid 0 --uname root --gname root \
			--no-xattrs --no-acls --no-mac-metadata \
			$$d $$d/binchk $$d/binchk.png $$d/binchk.desktop $$d/README.md $$d/LICENSE $$d/NOTICE \
			| gzip -n -9 > $(REL)/$$d.tar.gz; \
		d=binchk-$(VERSION)-windows-$$a; mkdir $(REL)/stage/$$d; \
		install -m 644 dist/binchk-windows-$$a.exe $(REL)/stage/$$d/binchk.exe; \
		install -m 644 README.md LICENSE NOTICE $(REL)/stage/$$d/; \
		touch -t $$stamp $(REL)/stage/$$d $(REL)/stage/$$d/*; \
		(cd $(REL)/stage && zip -q -X ../$$d.zip \
			$$d/ $$d/binchk.exe $$d/README.md $$d/LICENSE $$d/NOTICE); \
	done
	rm -rf $(REL)/stage
	cd $(REL) && shasum -a 256 *.zip *.tar.gz > SHA256SUMS
	@if zipinfo -1 $(REL)/binchk-$(VERSION)-macos.zip | grep -q '\._'; then \
		echo "$(REL): AppleDouble entries in the macOS zip" >&2; exit 1; fi
	@cat $(REL)/SHA256SUMS

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
