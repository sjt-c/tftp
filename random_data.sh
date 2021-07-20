#!/bin/sh

if [ -z "${1}" ]
then
	echo "Usage: random_data.sh <num bytes>"
	echo "Example: random_data.sh 512 > 512_bytes_of_random_data.txt"
	echo
	exit 1
fi

export LC_CTYPE=C
tr -dc '[:print:]' < /dev/urandom | dd bs="${1}" count=1 2>/dev/null
