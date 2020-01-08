#!/usr/bin/env bash

set -e

go test -race
for d in $(cat go.mod | grep userplex | grep replace | awk '{print $2}'); do
    go test -race $d
done
