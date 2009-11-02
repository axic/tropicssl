/*
 *  Diffie-Hellman-Merkle key exchange (client side)
 *
 *  Copyright (C) 2006-2007  Christophe Devine
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

#include "xyssl/net.h"
#include "xyssl/aes.h"
#include "xyssl/dhm.h"
#include "xyssl/rsa.h"
#include "xyssl/sha1.h"
#include "xyssl/havege.h"

#define SERVER_NAME "localhost"
#define SERVER_PORT 11999

int main( void )
{
    FILE *f;

    int ret, n, buflen;
    int server_fd = -1;

    unsigned char *p, *end;
    unsigned char buf[1024];
    unsigned char hash[20];

    havege_state hs;
    rsa_context rsa;
    dhm_context dhm;
    aes_context aes;

    memset( &rsa, 0, sizeof( rsa ) );
    memset( &dhm, 0, sizeof( dhm ) );

    /*
     * 1. Setup the RNG
     */
    printf( "\n  . Seeding the random number generator" );
    fflush( stdout );

    havege_init( &hs );

    /*
     * 2. Read the server's public RSA key
     */
    printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = rsa_read_public( &rsa, f ) ) != 0 )
    {
        printf( " failed\n  ! rsa_read_public returned %08x\n\n", ret );
        goto exit;
    }

    fclose( f );

    /*
     * 3. Initiate the connection
     */
    printf( "\n  . Connecting to tcp/%s/%d", SERVER_NAME,
                                             SERVER_PORT );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_connect returned %08x\n\n", ret );
        goto exit;
    }

    /*
     * 4a. First get the buffer length
     */
    printf( "\n  . Receiving the server's DH parameters" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );

    n = 2;
    if( ( ret = net_recv( server_fd, buf, &n ) ) != 0 )
    {
        printf( " failed\n  ! net_recv returned %08x\n\n", ret );
        goto exit;
    }

    n = buflen = ( buf[0] << 8 ) | buf[1];
    if( buflen < 1 || buflen > (int) sizeof( buf ) )
    {
        printf( " failed\n  ! Got an invalid buffer length\n\n" );
        goto exit;
    }

    /*
     * 4b. Get the DHM parameters: P, G and Ys = G^Xs mod P
     */
    if( ( ret = net_recv( server_fd, buf, &n ) ) != 0 )
    {
        printf( " failed\n  ! net_recv returned %08x\n\n", ret );
        goto exit;
    }

    p = buf, end = buf + buflen;

    if( ( ret = dhm_read_params( &dhm, &p, end ) ) != 0 )
    {
        printf( " failed\n  ! dhm_read_params returned %08x\n\n", ret );
        goto exit;
    }

    if( dhm.len < 64 || dhm.len > 256 )
    {
        ret = 1;
        printf( " failed\n  ! Invalid DHM modulus size\n\n" );
        goto exit;
    }

    /*
     * 5. Check that the server's RSA signature matches
     *    the SHA-1 hash of (P,G,Ys)
     */
    printf( "\n  . Verifying the server's RSA signature" );
    fflush( stdout );

    if( ( n = (int)( end - p ) ) != rsa.len )
    {
        ret = 1;
        printf( " failed\n  ! Invalid RSA signature size\n\n" );
        goto exit;
    }

    sha1( buf, (int)( p - 2 - buf ), hash );

    if( ( ret = rsa_pkcs1_verify( &rsa, RSA_SHA1,
                                  hash, 20, p, n ) ) != 0 )
    {
        printf( " failed\n  ! rsa_pkcs1_verify returned "
                "%08x\n\n", ret );
        goto exit;
    }

    /*
     * 6. Send our public value: Yc = G ^ Xc mod P
     */
    printf( "\n  . Sending own public value to server" );
    fflush( stdout );

    n = dhm.len;
    if( ( ret = dhm_make_public( &dhm, buf, n,
                                 havege_rand, &hs ) ) != 0 )
    {
        printf( " failed\n  ! dhm_make_public returned %08x\n\n", ret );
        goto exit;
    }

    if( ( ret = net_send( server_fd, buf, &n ) ) != 0 )
    {
        printf( " failed\n  ! net_recv returned %08x\n\n", ret );
        goto exit;
    }

    /*
     * 7. Derive the shared secret: K = Ys ^ Xc mod P
     */
    printf( "\n  . Shared secret: " );
    fflush( stdout );

    n = dhm.len;
    if( ( ret = dhm_calc_secret( &dhm, buf, &n ) ) != 0 )
    {
        printf( " failed\n  ! dhm_calc_secret returned %08x\n\n", ret );
        goto exit;
    }

    for( n = 0; n < 16; n++ )
        printf( "%02x", buf[n] );

    /*
     * 8. Setup the AES-256 decryption key
     *
     * This is an overly simplified example; best practice is
     * to hash the shared secret with a random value to derive
     * the keying material for the encryption/decryption keys
     * and MACs.
     */
    printf( "...\n  . Receiving and decrypting the ciphertext" );
    fflush( stdout );

    aes_set_key( &aes, buf, 256 );

    n = 16;
    if( ( ret = net_recv( server_fd, buf, &n ) ) != 0 )
    {
        printf( " failed\n  ! net_recv returned %08x\n\n", ret );
        goto exit;
    }

    aes_decrypt( &aes, buf, buf );  buf[16] = '\0';
    printf( "\n  . Plaintext is \"%s\"\n\n", buf );

exit:

    net_close( server_fd );
    rsa_free( &rsa );
    dhm_free( &dhm );

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
