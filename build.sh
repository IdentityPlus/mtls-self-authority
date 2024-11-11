#!/bin/bash

go build -C src -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -o ../bin/x86_64/ubuntu_24.04/selfauthority .
sudo ln -sf "$(pwd)/bin/x86_64/ubuntu_24.04/selfauthority" /usr/local/bin/selfauthority
