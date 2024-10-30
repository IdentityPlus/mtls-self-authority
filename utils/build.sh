#!/bin/bash

# build go with static linking (glibc libraries included)
# so it would work on multiple version of the same Linix flavor
go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"'