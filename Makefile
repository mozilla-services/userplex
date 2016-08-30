# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

PROJECT		:= go.mozilla.org/userplex
GO 			:= GOOS=$(OS) GOARCH=$(ARCH) GO15VENDOREXPERIMENT=1 go
GOGETTER	:= GOPATH=$(shell pwd)/.tmpdeps go get -d

all: test vet generate userplex

dev: lint cyclo all

userplex:
	$(GO) install $(PROJECT)

go_vendor_dependencies:
	glide install

test:
	$(GO) test $(PROJECT)/modules/...
	$(GO) test $(PROJECT)

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
