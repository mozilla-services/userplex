# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

GO 			:= GOOS=$(OS) GOARCH=$(ARCH) GO15VENDOREXPERIMENT=1 go
GOGETTER	:= GOPATH=$(shell pwd)/.tmpdeps go get -d
PROJECT     := go.mozilla.org/mozldap
GOLINT 		:= golint
GOVEND 		:= govend

all: vendor lint vet generate test install

install:
	$(GO) install $(PROJECT)

lint:
	$(GOLINT) $(PROJECT)

vet:
	$(GO) vet $(PROJECT)

test:
	$(GO) test -covermode=count -coverprofile=coverage.out $(PROJECT)

showcoverage: test
	$(GO) tool cover -html=coverage.out

vendor:
	$(GOVEND) -u

generate:
	$(GO) generate


