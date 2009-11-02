/*
 *  SSL server demonstration program
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

#ifdef WIN32
#include <windows.h>
#endif

#include <string.h>
#include <stdio.h>

#include "havege.h"
#include "testcert.h"
#include "ssl_v3.h"
#include "x509.h"
#include "net.h"

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2><p><center>Successful connection using: %s\r\n"

/*
 * Computing a safe DH-1024 prime takes ages,
 * so it's faster to use a precomputed value
 * (this one is only provided as an example).
 */
char *dhm_ext_modulus = 
    "E4004C1F94182000103D883A448B3F80" \
    "2CE4B44A83301270002C20D0321CFD00" \
    "11CCEF784C26A400F43DFB901BCA7538" \
    "F2C6B176001CF5A0FD16D2C48B1D0C1C" \
    "F6AC8E1DA6BCC3B4E1F96B0564965300" \
    "FFA1D0B601EB2800F489AA512C4B248C" \
    "01F76949A60BB7F00A40B1EAB64BDD48" \
    "E8A700D60B7F1200FA8E77B0A979DABF";

char *dhm_ext_generator = "2";

/*
 * sorted by order of preference
 */
int ciphers[] =
{
    TLS1_EDH_RSA_AES_256_SHA,
    SSL3_EDH_RSA_DES_168_SHA,
    TLS1_RSA_AES_256_SHA,
    SSL3_RSA_DES_168_SHA,
    SSL3_RSA_RC4_128_SHA,
    0
};

int main( void )
{
    int ret, len;
    int listen_fd;
    int client_fd;
    uchar buf[1024];
    havege_state hs;
    ssl_context ssl;
    x509_cert srvcert;
    rsa_context rsa;

    /*
     * => Initialize the RNG
     */
    printf( "\n  . Seeding the random nb. generator..." );
    fflush( stdout );

    havege_init( &hs );
    printf( " ok\n" );

    /*
     * => Load the certificates and private key
     */
    printf( "  . Loading the server cert. and key..." );
    fflush( stdout );

    memset( &srvcert, 0, sizeof( x509_cert ) );

    ret = x509_add_certs( &srvcert, (uchar *) test_srv_crt,
                                      strlen( test_srv_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  ! x509_add_certs returned %08x\n\n", ret );
        goto exit;
    }

    ret = x509_add_certs( &srvcert, (uchar *) test_ca_crt,
                                      strlen( test_ca_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  ! x509_add_certs returned %08x\n\n", ret );
        goto exit;
    }

    ret = x509_parse_key( &rsa, (uchar *) test_srv_key,
                                  strlen( test_srv_key ), NULL, 0 );
    if( ret != 0 )
    {
        printf( " failed\n  ! x509_parse_key returned %08x\n\n", ret );
        return( ret );
    }

    printf( " ok\n" );

    /*
     * => TCP bind()
     */
    printf( "  . Listen on https://localhost:4443..." );
    fflush( stdout );

    ret = net_bind( &listen_fd, NULL, 4443 );
    if( ret != 0 )
    {
        printf( " failed\n  ! net_bind returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * => TCP accept()
     */
#ifdef WIN32
    ShellExecute( NULL, "open", "https://localhost:4443/",
                  NULL, NULL, SW_SHOWNORMAL );
#endif

accept:

    printf( "  . Waiting for incoming connections..." );
    fflush( stdout );

    ret = net_accept( listen_fd, &client_fd, NULL );
    if( ret != 0 )
    {
        printf( " failed\n  ! net_accept returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

   /*
     * => Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    ret = ssl_init( &ssl, ciphers, havege_rand, &hs );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_init returned %08x\n\n", ret );
        goto exit;
    }

    ssl_set_io_files( &ssl, client_fd, client_fd );
    ssl_set_own_cert( &ssl, &srvcert, &rsa );
    ssl_set_ca_chain( &ssl, srvcert.next, NULL );

    ret = ssl_server_start( &ssl, SSL_VERIFY_NONE );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_server_start returned %08x\n\n", ret );
        ssl_close( &ssl );
        goto accept;
    }

    printf( " ok\n" );

    /*
     * => Read the HTTP Request
     */
    printf( "  < Read from client:" );

    memset( buf, 0, sizeof( buf ) );
    len = sizeof( buf ) - 1;
    if( ( ret = ssl_read( &ssl, buf, &len, 0 ) ) != 0 )
    {
        if( ret == ERR_NET_CONN_RESET )
            printf( " failed\n  ! Connection was reset by peer\n\n" );
        else
            printf( " failed\n  ! ssl_read returned %08x\n\n", ret );

        ssl_close( &ssl );
        goto accept;
    }

    printf( "\n\n%s", buf );

    /*
     * => Write the 200 Response
     */
    printf( "  > Write to client:" );

    len = sprintf( (char *) buf, HTTP_RESPONSE,
                   ssl_cipher_name( &ssl ) );
    ret = ssl_write( &ssl, buf, len );
    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_write returned %08x\n\n", ret );
        ssl_close( &ssl );
        goto accept;
    }

    printf( "\n\n%s\n", buf );

    ssl_close( &ssl );
    goto accept;

exit:

#ifdef WIN32
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
