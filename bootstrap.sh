#!/bin/sh
# (c) 2007 Arnaud Cornet

set -eu
LANG=C
export LANG

aclocal
autoconf
autoheader
touch NEWS README AUTHORS ChangeLog
automake --add-missing --copy -Wall

