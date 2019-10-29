# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

PROJECT		:= go.mozilla.org/userplex

all: test vet install

dev: lint cyclo all

install:
	go install $(PROJECT)

test:
	go test $(PROJECT)/modules/aws
	go test $(PROJECT)

lint:
	golint .
	golint modules/...

vet:
	go vet $(PROJECT)

cyclo:
	gocyclo -over 15 *.go modules/

.PHONY: all test clean install vendor
