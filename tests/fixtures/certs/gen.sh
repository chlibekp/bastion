#!/bin/sh
# Test certificates for the TLS tests: gen.sh DIR  (idempotent: files that exist are kept).
#   ca, ca2          two EC certificate authorities
#   ecdsa, rsa       server leaves for localhost and 127.0.0.1 (ecdsa-chain: leaf + CA)
#   expired          a server leaf whose validity ended in 2020
#   site-a, site-b   leaves for a.example and b.example; wild for *.wild.example; default
#   client           client leaf of ca; client-other of ca2; client-expired; client-revoked + crl.pem
# gen.sh DIR ocsp NAME URL  adds NAME.key/NAME.crt for localhost with an OCSP URL in its AIA, plus
# ocsp-signer for `openssl ocsp -rsigner`. Needs only the openssl command line tool.
set -eu
d=$1
mkdir -p "$d"
cd "$d"
O=${OPENSSL:-openssl}

ekey() { [ -f "$1.key" ] || "$O" ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null; }
rkey() { [ -f "$1.key" ] || "$O" genrsa -out "$1.key" 2048 2>/dev/null; }

# leaf NAME CN SAN-or-empty CA SERIAL USAGE [extra x509 options]
leaf() {
	name=$1 cn=$2 san=$3 ca=$4 serial=$5 usage=$6
	shift 6
	[ -f "$name.crt" ] && return 0
	{
		echo "basicConstraints=CA:false"
		echo "keyUsage=critical,digitalSignature,keyEncipherment"
		echo "extendedKeyUsage=$usage"
		[ -n "$san" ] && echo "subjectAltName=$san"
		[ -n "${AIA:-}" ] && echo "authorityInfoAccess=OCSP;URI:$AIA"
		true
	} >"$name.ext"
	"$O" req -new -key "$name.key" -subj "/CN=$cn" -out "$name.csr"
	"$O" x509 -req -in "$name.csr" -CA "$ca.crt" -CAkey "$ca.key" -set_serial "$serial" \
		-days 3650 -sha256 -extfile "$name.ext" -out "$name.crt" "$@" 2>/dev/null
}

mkca() {
	[ -f "$1.crt" ] && return 0
	ekey "$1"
	printf 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$1.ext"
	"$O" req -x509 -new -key "$1.key" -subj "/CN=Bastion test $1" -days 3650 -sha256 \
		-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
		-out "$1.crt"
}

if [ "${2:-}" = ocsp ]; then
	name=$3
	AIA=$4
	ekey "$name"
	leaf "$name" localhost "DNS:localhost,IP:127.0.0.1" ca 700 serverAuth
	ekey ocsp-signer
	AIA=
	leaf ocsp-signer "OCSP signer" "" ca 701 OCSPSigning
	exit 0
fi

mkca ca
mkca ca2

SRV="DNS:localhost,IP:127.0.0.1"
ekey ecdsa; leaf ecdsa localhost "$SRV" ca 101 serverAuth
rkey rsa; leaf rsa localhost "$SRV" ca 102 serverAuth
[ -f ecdsa-chain.crt ] || cat ecdsa.crt ca.crt >ecdsa-chain.crt
ekey expired; leaf expired localhost "$SRV" ca 103 serverAuth -not_before 20200101000000Z -not_after 20200102000000Z
ekey site-a; leaf site-a a.example "DNS:a.example" ca 111 serverAuth
ekey site-b; leaf site-b b.example "DNS:b.example" ca 112 serverAuth
ekey wild; leaf wild "*.wild.example" "DNS:*.wild.example" ca 113 serverAuth
ekey default; leaf default default.example "DNS:default.example" ca 114 serverAuth
ekey other; # a key that matches no certificate

ekey client; leaf client "client one" "" ca 201 clientAuth
ekey client-other; leaf client-other "client other" "" ca2 202 clientAuth
ekey client-expired; leaf client-expired "client expired" "" ca 203 clientAuth -not_before 20200101000000Z -not_after 20200102000000Z

# The revoked client needs a CA database, so it is signed with `openssl ca`.
if [ ! -f crl.pem ]; then
	[ -f index.txt ] || : >index.txt
	[ -f serial.txt ] || echo 0300 >serial.txt
	[ -f crlnumber.txt ] || echo 01 >crlnumber.txt
	cat >ca.cnf <<EOF
[ca]
default_ca = CA_default
[CA_default]
database = index.txt
serial = serial.txt
crlnumber = crlnumber.txt
default_md = sha256
default_crl_days = 3650
certificate = ca.crt
private_key = ca.key
new_certs_dir = .
unique_subject = no
policy = pol
copy_extensions = none
[pol]
commonName = supplied
EOF
	ekey client-revoked
	printf 'basicConstraints=CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' >client-revoked.ext
	"$O" req -new -key client-revoked.key -subj "/CN=client revoked" -out client-revoked.csr
	"$O" ca -batch -config ca.cnf -in client-revoked.csr -out client-revoked.crt -days 3650 \
		-extfile client-revoked.ext -notext 2>/dev/null
	"$O" ca -batch -config ca.cnf -revoke client-revoked.crt 2>/dev/null
	"$O" ca -batch -config ca.cnf -gencrl -out crl.pem 2>/dev/null
fi
