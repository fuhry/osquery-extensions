#!/bin/bash

private_keys=()
for bits in 256 384 521; do
	test -f ecdsa-p$bits.key || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-$bits -out ecdsa-p$bits.key
	private_keys+=("ecdsa-p$bits.key")
done

for bits in 2048 4096; do
	test -f rsa-$bits.key || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits -out rsa-$bits.key
	private_keys+=("rsa-$bits.key")
done

crts=()
for k in "${private_keys[@]}"; do
	crt="${k%.key}.crt"
	openssl req -new -key "$k" -subj "/CN=Test certificate for osquery x509_certificates table/" -days 36524 -x509 -out "$crt"
	crts+=("$crt")
done

cat "${crts[@]}" > all-crts.crt

