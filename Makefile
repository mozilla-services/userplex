# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

PROJECT		:= github.com/mozilla-services/userplex
GO 			:= GOOS=$(OS) GOARCH=$(ARCH) GO15VENDOREXPERIMENT=1 go
GOGETTER	:= GOPATH=$(shell pwd)/.tmpdeps go get -d

all: test vet generate userplex

dev: lint cyclo all

userplex:
	$(GO) install github.com/mozilla-services/userplex

go_vendor_dependencies:
	$(GOGETTER) github.com/mozilla-services/mozldap
	$(GOGETTER) gopkg.in/yaml.v2
	$(GOGETTER) github.com/aws/aws-sdk-go
	$(GOGETTER) github.com/zorkian/go-datadog-api
	$(GOGETTER) github.com/gorhill/cronexpr
	$(GOGETTER) golang.org/x/crypto/openpgp
	echo 'removing .git from vendored pkg and moving them to vendor'
	find .tmpdeps/src -name ".git" ! -name ".gitignore" -exec rm -rf {} \; || exit 0
	[ -d vendor ] && git rm -rf vendor/ || exit 0
	mkdir vendor/ || exit 0
	cp -ar .tmpdeps/src/* vendor/
	git add vendor/
	rm -rf .tmpdeps

test:
	$(GO) test github.com/mozilla-services/userplex/modules/...
	$(GO) test github.com/mozilla-services/userplex

lint:
	golint .
	golint modules/...

vet:
	$(GO) vet $(PROJECT)

generate:
	$(GO) generate

cyclo:
	gocyclo -over 15 *.go modules/

.PHONY: all test clean userplex
