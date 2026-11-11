PREFIX ?= /usr
DESTDIR ?=
VERSION ?= dev
GO ?= go

GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
PACKAGE_NAME = hub-net-$(VERSION)-$(GOOS)-$(GOARCH)

.PHONY: all build test package package-windows install integration-linux-package integration-multi-hub-linux integration-hn706-release integration-machine-restart-prepare integration-machine-restart-verify

all: build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.buildVersion=$(VERSION)" -o build/hub-net ./cmd/hub-net

test:
	$(GO) test ./...

package: build
	rm -rf "build/package/$(PACKAGE_NAME)"
	mkdir -p "build/package/$(PACKAGE_NAME)"
	cp build/hub-net README.md "build/package/$(PACKAGE_NAME)/"
	cp -R packaging "build/package/$(PACKAGE_NAME)/"
	chmod 0755 \
		"build/package/$(PACKAGE_NAME)/packaging/linux/install" \
		"build/package/$(PACKAGE_NAME)/packaging/linux/update" \
		"build/package/$(PACKAGE_NAME)/packaging/linux/check-for-updates" \
		"build/package/$(PACKAGE_NAME)/packaging/linux/uninstall"
	COPYFILE_DISABLE=1 tar --no-xattrs -C build/package -czf "build/$(PACKAGE_NAME).tar.gz" "$(PACKAGE_NAME)"
	@if command -v sha256sum >/dev/null 2>&1; then \
		cd build && sha256sum "$(PACKAGE_NAME).tar.gz" > "$(PACKAGE_NAME).tar.gz.sha256"; \
	else \
		cd build && shasum -a 256 "$(PACKAGE_NAME).tar.gz" > "$(PACKAGE_NAME).tar.gz.sha256"; \
	fi

# The Windows zip: hub-net.exe and its README (wireguard.dll comes from WireGuard's signed release,
# see packaging/windows/README.md). make package-windows GOARCH=arm64 VERSION=1.0.0
package-windows:
	rm -rf "build/package/hub-net-$(VERSION)-windows-$(GOARCH)"
	mkdir -p "build/package/hub-net-$(VERSION)-windows-$(GOARCH)"
	CGO_ENABLED=0 GOOS=windows GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags="-s -w -X main.buildVersion=$(VERSION)" \
		-o "build/package/hub-net-$(VERSION)-windows-$(GOARCH)/hub-net.exe" ./cmd/hub-net
	cp packaging/windows/README.md "build/package/hub-net-$(VERSION)-windows-$(GOARCH)/"
	cd build/package && rm -f "../hub-net-$(VERSION)-windows-$(GOARCH).zip" && \
		zip -qr "../hub-net-$(VERSION)-windows-$(GOARCH).zip" "hub-net-$(VERSION)-windows-$(GOARCH)"

install: build
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/bin"
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/lib/systemd/system"
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/lib/sysusers.d"
	install -d -m 0755 "$(DESTDIR)$(PREFIX)/lib/tmpfiles.d"
	install -m 0755 build/hub-net "$(DESTDIR)$(PREFIX)/bin/hub-net"
	install -m 0644 packaging/linux/hub-net.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/hub-net.service"
	install -m 0644 packaging/linux/hub-net.sysusers "$(DESTDIR)$(PREFIX)/lib/sysusers.d/hub-net.conf"
	install -m 0644 packaging/linux/hub-net.tmpfiles "$(DESTDIR)$(PREFIX)/lib/tmpfiles.d/hub-net.conf"

integration-linux-package:
	./integration/linux_package.sh

integration-multi-hub-linux:
	./integration/multi_hub_linux.sh

integration-hn706-release:
	../../hub-server/integration/hn706_release.sh

integration-machine-restart-prepare:
	HUB_NET_MACHINE_RESTART_ACCEPTANCE=1 ./integration/machine_restart.sh prepare

integration-machine-restart-verify:
	HUB_NET_MACHINE_RESTART_ACCEPTANCE=1 ./integration/machine_restart.sh verify
