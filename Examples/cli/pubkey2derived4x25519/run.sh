#!/bin/sh

export ENV_RAW_PUBKEY_LOCATION=./sample.d/pubkey-x25519-raw-32bytes.dat

mkdir -p sample.d


# creates dummy "salt" for test(use CSPRNG to get this for production)
test -f ./sample.d/salt4test.dat ||
  dd \
    if=/dev/urandom \
    of=./sample.d/salt4test.dat \
    bs=32 \
    count=1 \
    status=none

# creates dummy "pubkey" like 32 bytes if it does not exists
test -f "${ENV_RAW_PUBKEY_LOCATION}" ||
	dd \
		if=/dev/urandom \
		of="${ENV_RAW_PUBKEY_LOCATION}" \
		bs=32 \
		count=1 \
		status=none

./PubkeyToDerivedForX25519Cli
