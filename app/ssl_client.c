/*
 *  SSL client demonstration program
 *
 *  Copyright (C) 2006  Christophe Devine
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#ifdef _MSC_VER
#pragma comment(lib, "xyssl.lib")
#endif

#include <string.h>
#include <stdio.h>

#include "havege.h"
#include "ssl_v3.h"
#include "x509.h"
#include "net.h"

/*
 * XySSL.org CA certificate
 */
char xyssl_crt[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIID4DCCAsigAwIBAgIJAOLw9BMV1jxMMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNV\r\n"
"BAYTAkZSMQ4wDAYDVQQIEwVQYXJpczEOMAwGA1UEChMFWHlTU0wxJDAiBgNVBAMT\r\n"
"G1h5U1NMIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNjEwMzEyMjU5MjRaFw0x\r\n"
"NjEwMzEyMjU5MjRaMFMxCzAJBgNVBAYTAkZSMQ4wDAYDVQQIEwVQYXJpczEOMAwG\r\n"
"A1UEChMFWHlTU0wxJDAiBgNVBAMTG1h5U1NMIENlcnRpZmljYXRlIEF1dGhvcml0\r\n"
"eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKnprf1RQ7IYPI3FmI/h\r\n"
"f2EJGfaIP+Jt551VZWFrs3A56Nn4KS57zTAKZUA7YGbLwlAznfaphJ7SvENALeZR\r\n"
"/J0c/n9jwMpfXReQL7RVpgg/zlR+t2DUi3DAwigPZiHHCSJSBC73vpMc6uH0eV2d\r\n"
"itqjjUnJG5F8Zg9/gX4UMRAdlwGWqxvs+jc9i0XFKOEzga8+rONe6WvKyBM4e20I\r\n"
"HcO4BPF92d6sm4qLgyR4oXUkBz6NfDWX8ZdTvXuRaK9qMy1327cCT48sis9F6/eK\r\n"
"QAxx0VHlqGTtxDYjHJPsMLNejuyUDvsaC8TMCSpFTXpMTUvJdmxsF1LZWmIo5lY5\r\n"
"zh0CAwEAAaOBtjCBszAdBgNVHQ4EFgQUBlVzoNJrkkgPkJ8xjuFvVP2E4GswgYMG\r\n"
"A1UdIwR8MHqAFAZVc6DSa5JID5CfMY7hb1T9hOBroVekVTBTMQswCQYDVQQGEwJG\r\n"
"UjEOMAwGA1UECBMFUGFyaXMxDjAMBgNVBAoTBVh5U1NMMSQwIgYDVQQDExtYeVNT\r\n"
"TCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCCQDi8PQTFdY8TDAMBgNVHRMEBTADAQH/\r\n"
"MA0GCSqGSIb3DQEBBQUAA4IBAQCGD65b2l5BASFsPvlrcRnLZu/99eWTVAJwJbbD\r\n"
"VhPAQiET0W4U/85EDK7uoFo/SEjyMB/m4T20A8FIDaK7jBPo/1gtbuQjGMRl7h+z\r\n"
"F2iGuNhZ6Td26Uzqclt3oiFtSvDRoZ/9kqkEy7Lrs7FBzOmvfTvrqvADf7cLMa2D\r\n"
"ri/otDpzPr4XoDnwd4C+4bQC/Gr3Uder4VAeTOJtKdGqfYLvPwPSPVBDuVLUybKi\r\n"
"8cMAT6p9IG1e12u6vFqcBT/I67Q0bGU6gzVVz9ZVULXOYZMjjLAfVXC1gesUH2WT\r\n"
"gTEAnEBkSRrkfAi+RezoEFAbmEl3fPt09dwSPku3x7cB3zaJ\r\n"
"-----END CERTIFICATE-----\r\n";

#define GET_REQUEST \
    "HEAD /hello/ HTTP/1.1\r\n" \
    "Host: xyssl.org\r\n\r\n"

int main( void )
{
    int ret;
    uint len;
    uint ciphers[3];
    uchar buf[1024];
    havege_state hs;
    ssl_context ssl;
    x509_cert cacert;

    /*
     * ===== Init RNG & Ciphersuites =====
     */
    printf( "\n  . Setting up the RNG and SSL state..." );
    fflush( stdout );

    havege_init( &hs );

    ciphers[0] = TLS1_RSA_AES_256_SHA;
    ciphers[1] = SSL3_RSA_DES_192_SHA;
    ciphers[2] = 0;

    ret = ssl_init( &ssl, ciphers, havege_rand, &hs );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_init returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * ===== Load Trusted CA =====
     */
    printf( "  . Loading the CA root  certificate..." );
    fflush( stdout );

    memset( &cacert, 0, sizeof( x509_cert ) );

    ret = x509_add_certs( &cacert, (uchar *) xyssl_crt,
                                     strlen( xyssl_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  ! x509_add_certs returned %08x\n\n", ret );
        goto exit;
    }

    ssl_set_ca_chain( &ssl, &cacert, "xyssl.org" );

    printf( " ok\n" );

    /*
     * ===== TCP Connect =====
     */
    printf( "  . Connecting  to tcp/xyssl.org/443..." );
    fflush( stdout );

    ret = net_connect( &ssl.read_fd, "xyssl.org", 443 );
    if( ret != 0 )
    {
        printf( " failed\n  ! net_connect returned %08x\n\n", ret );
        goto exit;
    }

    ssl.write_fd = ssl.read_fd;

    printf( " ok\n" );

    /*
     * ===== Handshake =====
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    ret = ssl_client_start( &ssl, SSL_VERIFY_OPTIONAL );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_client_start returned %08x\n\n", ret );
        goto exit2;
    }

    printf( " ok\n" );

    printf( "    [ Cipher is %s ]\n",
            ( ssl.cipher == TLS1_RSA_AES_256_SHA )
            ? "TLS1_RSA_AES_256_SHA"
            : "SSL3_RSA_DES_192_SHA" );

    /*
     * ===== X509 Cert. Verify =====
     */
    printf( "  . Verifying peer X.509 certificate..." );

    if( ssl.verify_result != 0 )
    {
        printf( " failed\n" );

        if( ( ssl.verify_result & BADCERT_HAS_EXPIRED ) != 0 )
            printf( "  ! server certificate has expired\n" );

        if( ( ssl.verify_result & BADCERT_CN_MISMATCH ) != 0 )
            printf( "  ! CN mismatch (expected CN=xyssl.org)\n" );

        if( ( ssl.verify_result & BADCERT_NOT_TRUSTED ) != 0 )
            printf( "  ! server signature is invalid\n" );

        printf( "\n" );
    }
    else
        printf( " ok\n" );

    /*
     * ===== Write the GET Request =====
     */
    printf( "  > Write to server:" );

    ret = ssl_write( &ssl, (uchar *) GET_REQUEST,
                             strlen( GET_REQUEST ) );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_write returned %08x\n\n", ret );
        goto exit2;
    }

    printf( "\n\n%s", GET_REQUEST );

    /*
     * ====== Read the HTTP Response =====
     */
    printf( "  < Read from server:" );

    memset( buf, 0, sizeof( buf ) );
    len = sizeof( buf ) - 1;
    if( ( ret = ssl_read( &ssl, buf, &len, 0 ) ) != 0 )
    {
        printf( " failed\n  ! ssl_read returned %08x\n\n", ret );
        goto exit2;
    }

    printf( "\n\n%s", buf );

exit2:

    ssl_close( &ssl );
    ssl_free(  &ssl );

exit:

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
