#!/bin/bash

CA_DIR="./demoCA"

echo "=== Initialize CA environment and generate CA key/certificate ==="

mkdir -p $CA_DIR/private $CA_DIR/certs $CA_DIR/newcerts
chmod 755 $CA_DIR/private

# Initialize index.txt, serial, crlnumber
touch $CA_DIR/index.txt
echo 1000 > $CA_DIR/serial
echo 1000 > $CA_DIR/crlnumber

# Create a openssl.cnf for CA environment
OPENSSL_CNF=$CA_DIR/openssl.cnf
cat > $OPENSSL_CNF <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $CA_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl.pem
private_key       = \$dir/private/cakey.pem
certificate       = \$dir/certs/cacert.pem
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
default_crl_days  = 30
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
default_md          = sha256
prompt              = no
distinguished_name  = dn

[ dn ]
CN = Test CA

EOF

# Generate CA private key
openssl genpkey -algorithm RSA -out $CA_DIR/private/cakey.pem

# Generate self-signed CA certificate
openssl req -new -x509 -key $CA_DIR/private/cakey.pem -out $CA_DIR/certs/cacert.pem -days 3650 -config $OPENSSL_CNF

echo "===== CA key and certificate generation completed ====="

echo "===== Generating CRL ====="
openssl ca -gencrl -out $CA_DIR/crl.pem -config $OPENSSL_CNF

echo "===== CRL generation completed ====="
echo "CRL file location: $CA_DIR/crl.pem"

echo "CRL details:"
openssl crl -in $CA_DIR/crl.pem -text -noout