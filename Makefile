# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

PROJECT		:= go.mozilla.org/userplex

all: test vet install

dev: lint cyclo all

install:
	go install $(PROJECT)

test:
	./test.sh

lint:
	golint .
	golint modules/...

vet:
	go vet $(PROJECT)

cyclo:
	gocyclo -over 15 *.go modules/

deb-pkg: install
	rm -rf tmppkg
	mkdir -p tmppkg/usr/local/bin
	cp $$GOPATH/bin/sops tmppkg/usr/local/bin/
	fpm -C tmppkg -n sops --license MPL2.0 --vendor mozilla \
		--description "Userplex manages users in various systems based on a LDAP-like source" \
		-m "AJ Bahnken <ajvb@mozilla.com>" \
		--url https://go.mozilla.org/userplex \
		--architecture x86_64 \
		-v "$$(git describe --abbrev=0 --tags)" \
		-s dir -t deb .

rpm-pkg: install
	rm -rf tmppkg
	mkdir -p tmppkg/usr/local/bin
	cp $$GOPATH/bin/sops tmppkg/usr/local/bin/
	fpm -C tmppkg -n sops --license MPL2.0 --vendor mozilla \
		--description "Userplex manages users in various systems based on a LDAP-like source" \
		-m "AJ Bahnken <ajvb@mozilla.com>" \
		--url https://go.mozilla.org/userplex \
		--architecture x86_64 \
		-v "$$(git describe --abbrev=0 --tags)" \
		-s dir -t rpm .

.PHONY: all test clean install vendor
