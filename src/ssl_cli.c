/*
 *  SSLv3/TLSv1 client-side functions
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
#include <stdlib.h>
#include <time.h>

#include "ssl_v3.h"
#include "sha1.h"
#include "rsa.h"
#include "md5.h"

int ssl_write_client_hello( ssl_context *ssl )
{
    uchar *buf;
    uint i, n;
    time_t t;

     md5_starts( &ssl->hs_md5  );
    sha1_starts( &ssl->hs_sha1 );

    ssl->major_version = SSLV3_MAJOR_VERSION;
    ssl->minor_version = SSLV3_MINOR_VERSION;

    ssl->max_client_ver[0] = SSLV3_MAJOR_VERSION;
    ssl->max_client_ver[1] = TLS10_MINOR_VERSION;

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   highest version supported
     *     6  .   9   current UNIX time
     *    10  .  37   random bytes
     */
    buf = ssl->out_msg;

    memcpy( buf + 4, ssl->max_client_ver, 2 );

    t = time( NULL );
    buf[6] = (uchar)(t >> 24);
    buf[7] = (uchar)(t >> 16);
    buf[8] = (uchar)(t >>  8);
    buf[9] = (uchar)(t      );

    srand( (unsigned int) t );
    for( i = 4; i < 32; i++ )
        buf[i + 6] = (uchar) rand();

    memcpy( ssl->randbytes, buf + 6, 32 );

    /*
     *    38  .  38   sess.id length (0)
     *    39  .  40   cipherlist length
     *    41  .   n   cipherlist
     *     n  . n+1   compression (NULL)
     */
    buf[38] = n = i = 0;
    while( ssl->cipherlist[i] != 0 )
    {
        buf[41 + n] = (uchar)( ssl->cipherlist[i] >> 8 );
        buf[42 + n] = (uchar)  ssl->cipherlist[i];
        n += 2; i++;
    }

    buf[39] = n >> 8;
    buf[40] = n;

    buf[41 + n] = 1;
    buf[42 + n] = SSL_COMPRESS_NULL;

    ssl->out_msglen  = 43 + n;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CLIENT_HELLO;

    return( ssl_write_record( ssl, 0 ) );
}

int ssl_parse_server_hello( ssl_context *ssl )
{
    int ret;
    uint i, n;
    uchar *buf;

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     */
    buf = ssl->in_msg;

    if( ( ret = ssl_read_record( ssl, 0 ) ) != 0 )
        return( ret );

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        return( ERR_SSL_UNEXPECTED_MESSAGE );

    if( ssl->hslen < 42 ||
        buf[0] != SSL_HS_SERVER_HELLO ||
        buf[4] != SSLV3_MAJOR_VERSION ||
        ( buf[5] != SSLV3_MINOR_VERSION &&
          buf[5] != TLS10_MINOR_VERSION ) )
        return( ERR_SSL_BAD_HS_SERVER_HELLO );

    ssl->minor_version = buf[5];

    memcpy( ssl->randbytes + 32, buf + 6, 32 );

    /*
     *    38  .  38   session id length
     *    39  . 38+n  session id
     *   39+n . 40+n  chosen cipher
     *   41+n . 41+n  chosen compression alg.
     */
    n = buf[38];
    if( ssl->hslen != 42 + n )
        return( ERR_SSL_BAD_HS_SERVER_HELLO );

    ssl->cipher = ( buf[39 + n] << 8 ) | buf[40 + n];

    i = 0;
    while( 1 )
    {
        if( ssl->cipherlist[i] == 0 )
            return( ERR_SSL_BAD_HS_SERVER_HELLO );

        if( ssl->cipherlist[i++] == ssl->cipher )
            break;
    }

    if( buf[41 + n] != SSL_COMPRESS_NULL )
        return( ERR_SSL_BAD_HS_SERVER_HELLO );

    return( 0 );
}

int ssl_parse_certificate_request( ssl_context *ssl )
{
    int ret;

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   SSL version
     *     6  .   6   cert type count
     *     7  .. n-1  cert types
     *     n  .. n+1  length of all DNs
     *    n+2 .. n+3  length of DN 1
     *    n+4 .. ...  Distinguished Name #1
     *    ... .. ...  length of DN 2, etc.
     */
    if( ( ret = ssl_read_record( ssl, 0 ) ) != 0 )
        return( ret );

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        return( ERR_SSL_UNEXPECTED_MESSAGE );

    if( ssl->in_msg[0] == SSL_HS_CERTIFICATE_REQUEST )
    {
        ssl->client_auth = 1;

        if( ( ret = ssl_read_record( ssl, 0 ) ) != 0 )
            return( ret );

        if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
            return( ERR_SSL_UNEXPECTED_MESSAGE );
    }

    return( 0 );
}

int ssl_parse_server_key_exchange( ssl_context *ssl )
{
    /*
     * TODO: handle Ephemeral Diffie-Hellman KEX
     */
    ssl = NULL;

    return( 0 );
}

int ssl_parse_server_hello_done( ssl_context *ssl )
{
    if( ssl->hslen != 4 ||
        ssl->in_msg[0] != SSL_HS_SERVER_HELLO_DONE )
        return( ERR_SSL_BAD_HS_SERVER_HELLO_DONE );

    return( 0 );
}

int ssl_write_client_key_exchange( ssl_context *ssl )
{
    int ret;
    uint i, n;
    ulong *p;

    /*
     * ATM, only straight RSA key exchange is supported.
     */
    n = ssl->peer_cert->rsa.len;
    p = (ulong *) ssl->premaster;

    for( i = 0; i < 48 / sizeof( ulong ); i++ )
        p[i] = ssl->rng_func( ssl->rng_state )
             * ssl->rng_func( ssl->rng_state );

    memcpy( ssl->premaster, ssl->max_client_ver, 2 );

    i = 4;
    if( ssl->minor_version != SSLV3_MINOR_VERSION )
    {
        /*
         * Thanks to the IETF folks for this useless length field.
         */
        ssl->out_msg[4] = n >> 8;
        ssl->out_msg[5] = n;
        i += 2;
    }

    if( ( ret = rsa_pkcs1_encrypt( &ssl->peer_cert->rsa,
                                    ssl->premaster, 48,
                                    ssl->out_msg + i, n ) ) != 0 )
        return( ret );

    ssl_derive_keys( ssl );

    ssl->out_msglen  = i + n;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CLIENT_KEY_EXCHANGE;

    return( ssl_write_record( ssl, 0 ) );
}

int ssl_write_certificate_verify( ssl_context *ssl )
{
    uint n;
    uchar sig[512];
    md5_context md5;
    sha1_context sha1;

    if( ssl->client_auth == 0 || ssl->own_key == NULL )
        return( 0 );

    n = ssl->own_key->len;

    if( n < 64 || n > sizeof( sig ) )
        return( ERR_SSL_INVALID_MODULUS_SIZE );

    /*
     * SSLv3/TLSv1 does not conform to PKCS1v1.5, so rsa_pkcs1_sign
     * cannot be used directly; we have to take care of hashing and
     * message padding issues here.
     */
    sig[0] = 0;
    sig[1] = RSA_SIGN;
    memset( sig + 2, 0xFF, n - 38 );

    memcpy( &md5,  &ssl->hs_md5 , sizeof(  md5_context ) );
    memcpy( &sha1, &ssl->hs_sha1, sizeof( sha1_context ) );

     md5_finish(  &md5, sig + n - 36 );
    sha1_finish( &sha1, sig + n - 20 );

    if( rsa_private( ssl->own_key, sig, n, sig, n ) != 0 )
        return( ERR_RSA_SIGN_FAILED );

    ssl->out_msglen  = 4 + n;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE_VERIFY;
    memcpy( ssl->out_msg + 4, sig, n );

    return( ssl_write_record( ssl, 0 ) );
}

/*
 * Perform an SSL handshake with the server; server_verify may be:
 *
 *  SSL_VERIFY_NONE: the server certificate is not checked
 *
 *  SSL_VERIFY_OPTIONAL: server certificate is checked, however the
 *                       handshake continues even if verification failed
 *                       (you may want to check ssl->verify_result after)
 *
 *  SSL_VERIFY_REQUIRED: server *must* present a valid certificate,
 *                       handshake is aborted if verification failed.
 *
 * This function returns 0 when successful, or an SSL error code.
 */
int ssl_client_start( ssl_context *ssl, int server_verify )
{
    int ret;

    ssl->endpoint    = SSL_IS_CLIENT;
    ssl->verify_mode = server_verify;

    /*
     *  -->  ClientHello
     */
    if( ( ret = ssl_write_client_hello( ssl ) ) != 0 )
        return( ret );

    /*
     *  <--  ServerHello
     *       Certificate
     *      (CertificateRequest)
     *      (ServerKeyExchange)
     *       ServerHelloDone
     */

    if( ( ret = ssl_parse_server_hello( ssl ) )         != 0 ||
        ( ret = ssl_parse_certificate( ssl ) )          != 0 ||
        ( ret = ssl_parse_certificate_request( ssl ) )  != 0 ||
        ( ret = ssl_parse_server_key_exchange( ssl ) )  != 0 ||
        ( ret = ssl_parse_server_hello_done( ssl ) )    != 0 )
        return( ret );

    /*
     *  --> (Certificate/Alert)
     *       ClientKeyExchange
     *      (CertificateVerify)
     *       ChangeCipherSpec
     *       Finished
     */
    if( ( ret = ssl_write_certificate( ssl ) )         != 0 ||
        ( ret = ssl_write_client_key_exchange( ssl ) ) != 0 ||
        ( ret = ssl_write_certificate_verify( ssl ) )  != 0 ||
        ( ret = ssl_write_change_cipher_spec( ssl ) )  != 0 ||
        ( ret = ssl_write_finished( ssl ) )            != 0 )
        return( ret );

    /*
     *  <--  ChangeCipherSpec
     *       Finished
     */
    if( ( ret = ssl_parse_change_cipher_spec( ssl ) )   != 0 ||
        ( ret = ssl_parse_finished( ssl ) )             != 0 )
        return( ret );

    return( 0 );
}
