#!/bin/bash
#
# Shell-Script which creates a symbolic hash-link for each CA certificate
# and each CRL in the given directory.
# Copyright (C) 2003 Mario Strasser <mast@gmx.net>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# $Id$
#

OPENSSL="openssl"

# function to create the hash link
function mk_link()
{
  nr=0
  while [ -e $hash$nr ]; do
    if [ $file -ef $hash$nr ] || [ -h $file ]; then
      break;
    fi
    nr=`expr $nr + 1`
  done
  if [ ! $file -ef $hash$nr ] && [ ! -h $file ]; then
    ln -s $file $hash$nr
  fi
}

# change to the target directory
if [ $1 ]; then
  if [ -d $1 ]; then
    cd $1
  else
    echo "Error: $1 is not a valid directory!"
    exit -1
  fi
fi
# test the presence of openssl
if [ -z "`$OPENSSL version 2> /dev/null`" ]
then
	echo "$OPENSSL not found! install openssl first"
	exit -1
fi
# process all files
for file in *; do
  hash=`$OPENSSL x509 -inform pem -in $file -noout -hash 2> /dev/null`
  if [ ! -z "$hash" ]; then
    is_ca=`$OPENSSL x509 -inform pem -in $file -noout -text | grep 'CA:TRUE'`
    if [ ! -z "$is_ca" ]; then
      hash=$hash.
      mk_link
    fi
    continue
  fi
  hash=`$OPENSSL x509 -inform der -in $file -noout -hash 2> /dev/null`
  if [ ! -z "$hash" ]; then
    is_ca=`$OPENSSL x509 -inform der -in $file -noout -text | grep 'CA:TRUE'`
    if [ ! -z "$is_ca" ]; then
      hash=$hash.
      mk_link
    fi
    continue
  fi
  hash=`$OPENSSL crl -inform pem -in $file -noout -hash 2> /dev/null`
  if [ ! -z "$hash" ]; then
    hash=$hash.r
    mk_link
    continue
  fi
  hash=`$OPENSSL crl -inform der -in $file -noout -hash 2> /dev/null`
  if [ ! -z "$hash" ]; then
    hash=$hash.r
    mk_link
    continue
  fi

  # nothing can be done with the file
  echo "we got a problem with: $file"
done

exit 0
