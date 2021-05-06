#!/bin/bash
make
set -x
cp ./runc /usr/bin/mvrunc
ln -sf /opt/memverge/sbin/mvsnap /usr/local/sbin/criu
ls -al /usr/local/sbin/criu
ln -sf /usr/bin/mvrunc /usr/bin/runc
ls -al /usr/bin/runc
