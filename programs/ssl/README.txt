

                How to setup your own Certificate Authority
                ===========================================



    1. Configure OpenSSL
    --------------------

First of all, create sslconf.txt in the current directory
(a basic example is provided at the end of this file). Then
you need to create the database and a starting serial number:

$ touch index
$ echo "01" > serial


    2. Generate the CA certificate
    ------------------------------

$ openssl req -config sslconf.txt -days 3653 -x509 -newkey rsa:2048 \
              -set_serial 0 -text -keyout test-ca.key -out test-ca.crt


    3. Generate the private key and certificate request
    ---------------------------------------------------

$ openssl genrsa -out client.key 2048
$ openssl req -config sslconf.txt -new -key client.key -out client.req


    4. Issue and sign the certificate
    ---------------------------------

$ openssl ca -config sslconf.txt -in client.req -out client.crt


    5. To revoke a certificate and update the CRL
    ---------------------------------------------

$ openssl ca -config sslconf.txt -revoke client.crt
$ openssl ca -config sslconf.txt -gencrl -out crl.pem


    6. To display a certificate and verify its validity
    ---------------------------------------------------

$ openssl x509 -in client.crt -text -noout
$ cat test-ca.crt crl.pem > cacrl-temp.pem
$ openssl verify -CAfile cacrl-temp.pem -crl_check client.crt


    7. To export a certificate into a .pfx file
    -------------------------------------------

$ openssl pkcs12 -export -in client.crt -inkey client.key -out client.pfx


##================================================================
##============== Example OpenSSL configuration file ==============
##================================================================

#  References:
#
#  /etc/ssl/openssl.conf
#  http://www.openssl.org/docs/apps/config.html
#  http://www.openssl.org/docs/apps/x509v3_config.html

[ ca ]
default_ca              = my_ca

[ my_ca ]
certificate             = test-ca.crt
private_key             = test-ca.key
database                = index
serial                  = serial

new_certs_dir           = .
default_crl_days        = 30
default_days            = 365
default_md              = sha1
policy                  = my_policy
x509_extensions         = v3_usr

[ my_policy ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
distinguished_name      = my_req_dn
x509_extensions         = v3_ca

[ my_req_dn ]
countryName             = Country Name..............
countryName_min         = 2
countryName_max         = 2
stateOrProvinceName     = State or Province Name....
localityName            = Locality Name.............
0.organizationName      = Organization Name.........
organizationalUnitName  = Org. Unit Name............
commonName              = Common Name (required)....
commonName_max          = 64
emailAddress            = Email Address.............
emailAddress_max        = 64

[ v3_ca ]
basicConstraints        = CA:TRUE
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer:always

[ v3_usr ]
basicConstraints        = CA:FALSE
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer

