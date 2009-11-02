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

#include <string.h>
#include <stdio.h>

#include "havege.h"
#include "testcert.h"
#include "ssl_v3.h"
#include "x509.h"
#include "net.h"

/*
 * change the following to connect to another server
 */
#define SERVER_CN "xyssl.org"

#define GET_REQUEST \
    "HEAD /hello/ HTTP/1.1\r\nHost: %s\r\n\r\n"

uint ciphers[] =
{
    TLS1_RSA_AES_256_SHA,
    SSL3_RSA_DES_192_SHA,
    SSL3_RSA_RC4_128_SHA,
    0
};

int main( void )
{
    int ret;
    int server_fd;

    uint len;
    uchar buf[1024];

    havege_state hs;
    ssl_context ssl;
    x509_cert cacert;

    /*
     * == Initialize the RNG ==
     */
    printf( "\n  . Seeding the random nb. generator..." );
    fflush( stdout );

    havege_init( &hs );
    printf( " ok\n" );

    /*
     * == Load the trusted CA ==
     */
    printf( "  . Loading the CA root  certificate..." );
    fflush( stdout );

    memset( &cacert, 0, sizeof( x509_cert ) );

    ret = x509_add_certs( &cacert, (uchar *) xyssl_ca_crt,
                                     strlen( xyssl_ca_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  ! x509_add_certs returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * === TCP connect() ===
     */
    printf( "  . Connecting  to tcp/%s/443...", SERVER_CN );
    fflush( stdout );

    ret = net_connect( &server_fd, SERVER_CN, 443 );
    if( ret != 0 )
    {
        printf( " failed\n  ! net_connect returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * == Handshake ==
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    ret = ssl_init( &ssl, ciphers, havege_rand, &hs );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_init returned %08x\n\n", ret );
        goto exit;
    }

    ssl_set_io_files( &ssl, server_fd, server_fd );
    ssl_set_ca_chain( &ssl, &cacert, SERVER_CN );

    ret = ssl_client_start( &ssl, SSL_VERIFY_OPTIONAL );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_client_start returned %08x\n\n", ret );
        ssl_close( &ssl );
        goto exit;
    }

    printf( " ok\n" );

    printf( "    [ Cipher is %s ]\n",
        ( ssl.cipher == TLS1_RSA_AES_256_SHA ) ? "TLS1_RSA_AES_256_SHA" :
        ( ssl.cipher == SSL3_RSA_DES_192_SHA ) ? "SSL3_RSA_DES_192_SHA" :
                                                 "SSL3_RSA_RC4_128_SHA" );

    /*
     * == X.509 Cert. signature verify ==
     */
    printf( "  . Verifying peer X.509 certificate..." );

    if( ssl.verify_result != 0 )
    {
        printf( " failed\n" );

        if( ( ssl.verify_result & BADCERT_HAS_EXPIRED ) != 0 )
            printf( "  ! server certificate has expired\n" );

        if( ( ssl.verify_result & BADCERT_CN_MISMATCH ) != 0 )
            printf( "  ! CN mismatch (expected CN=%s)\n", SERVER_CN );

        if( ( ssl.verify_result & BADCERT_NOT_TRUSTED ) != 0 )
            printf( "  ! server signature is invalid\n" );

        printf( "\n" );
    }
    else
        printf( " ok\n" );

    /*
     * == Write the GET Request ==
     */
    printf( "  > Write to server:" );

    len = sprintf( (char *) buf, GET_REQUEST, SERVER_CN );
    ret = ssl_write( &ssl, buf, len );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_write returned %08x\n\n", ret );
        ssl_close( &ssl );
        goto exit;
    }

    printf( "\n\n%s", buf );

    /*
     * == Read the HTTP Response ==
     */
    printf( "  < Read from server:" );

    memset( buf, 0, sizeof( buf ) );
    len = sizeof( buf ) - 1;
    if( ( ret = ssl_read( &ssl, buf, &len, 0 ) ) != 0 )
    {
        printf( " failed\n  ! ssl_read returned %08x\n\n", ret );
        ssl_close( &ssl );
        goto exit;
    }

    printf( "\n\n%s", buf );
    ssl_close( &ssl );

exit:

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
