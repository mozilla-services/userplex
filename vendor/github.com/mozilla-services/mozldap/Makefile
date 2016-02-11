# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

GO 			:= GOOS=$(OS) GOARCH=$(ARCH) GO15VENDOREXPERIMENT=1 go
GOGETTER	:= GOPATH=$(shell pwd)/.tmpdeps go get -d

all: test install

install:
	$(GO) install github.com/mozilla-services/mozldap

go_vendor_dependencies:
	$(GOGETTER) gopkg.in/ldap.v2
	$(GOGETTER) github.com/howeyc/gopass
	echo 'removing .git from vendored pkg and moving them to vendor'
	find .tmpdeps/src -type d -name ".git" ! -name ".gitignore" -exec rm -rf {} \; || exit 0
	cp -ar .tmpdeps/src/* vendor/
	rm -rf .tmpdeps
