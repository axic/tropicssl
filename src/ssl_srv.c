/*
 *  SSLv3/TLSv1 server-side functions
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
#include "net.h"

int ssl_parse_client_hello( ssl_context *ssl )
{
    int ret, i, j, n;
    int ciph_len, sess_len;
    int chal_len, comp_len;
    uchar *buf;

    buf = ssl->in_hdr;

    if( ( ret = net_read_all( ssl->read_fd, buf, 5 ) ) != 0 )
        return( ret );

    if( ( buf[0] & 0x80 ) != 0 )
    {
        /*
         * SSLv2 Client Hello
         *
         * Record layer:
         *     0  .   1   message length
         *
         * SSL layer:
         *     2  .   2   message type
         *     3  .   4   protocol version
         */
        if( buf[0] != 0x80 || buf[1] < 17 ||
            buf[2] != SSL_HS_CLIENT_HELLO ||
            buf[3] != SSLV3_MAJOR_VERSION )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        memcpy( ssl->max_ver, buf + 3, 2 );

        ssl->major_version = SSLV3_MAJOR_VERSION;
        ssl->minor_version = ( buf[4] <= TLS10_MINOR_VERSION )
                             ? buf[4]  : TLS10_MINOR_VERSION;

        n = (int) buf[1] - 3;

        if( ( ret = net_read_all( ssl->read_fd, buf + 5, n ) ) != 0 )
            return( ret );

         md5_starts( &ssl->hs_md5  );
         md5_update( &ssl->hs_md5 , buf + 2, n + 3 );
        sha1_starts( &ssl->hs_sha1 );
        sha1_update( &ssl->hs_sha1, buf + 2, n + 3 );

        /*
         *     5  .   6   cipherlist length
         *     7  .   8   session id length
         *     9  .  10   challenge length
         *    11  .  ..   cipherlist
         *    ..  .  ..   session id
         *    ..  .  ..   challenge
         */
        ciph_len = ( (int) buf[5] << 8 ) | buf[ 6];
        sess_len = ( (int) buf[7] << 8 ) | buf[ 8];
        chal_len = ( (int) buf[9] << 8 ) | buf[10];

        if( ciph_len  < 3 || ciph_len > 192 || ( ciph_len % 3 ) != 0 )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        if( sess_len != 0 || chal_len < 8 || chal_len > 32 )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        if( n != 6 + ciph_len + sess_len + chal_len )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        memset( ssl->randbytes, 0, 32 - chal_len );
        memcpy( ssl->randbytes  +  32 - chal_len,
                buf + 11 + ciph_len, chal_len );

        for( i = 0; ssl->cipherlist[i] != 0; i++ )
        {
            for( j = 0; j < ciph_len; j += 3 )
            {
                if( buf[11 + j] == 0 &&
                    buf[12 + j] == 0 &&
                    buf[13 + j] == ssl->cipherlist[i] )
                {
                    ssl->cipher  = ssl->cipherlist[i];
                    return( 0 );
                }
            }
        }
    }
    else
    {
        /*
         * SSLv3 Client Hello
         *
         * Record layer:
         *     0  .   0   message type
         *     1  .   2   protocol version
         *     3  .   4   message length
         */
        if( buf[0] != SSL_MSG_HANDSHAKE   ||
            buf[1] != SSLV3_MAJOR_VERSION ||
            buf[3] != 0 || buf[4] < 45 )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        ssl->major_version = SSLV3_MAJOR_VERSION;
        ssl->minor_version = ( buf[2] <= TLS10_MINOR_VERSION )
                             ? buf[2]  : TLS10_MINOR_VERSION;

        n = (int) buf[4];
        buf = ssl->in_msg;

        if( ( ret = net_read_all( ssl->read_fd, buf, n ) ) != 0 )
            return( ret );

         md5_starts( &ssl->hs_md5  );
         md5_update( &ssl->hs_md5 , buf, n );
        sha1_starts( &ssl->hs_sha1 );
        sha1_update( &ssl->hs_sha1, buf, n );

        /*
         * SSL layer:
         *     0  .   0   handshake type
         *     1  .   3   handshake length
         *     4  .   5   protocol version
         *     6  .   9   UNIX time()
         *    10  .  37   random bytes
         *    38  .  38   session id length
         *    39  . 38+x  session id
         *   39+x . 40+x  cipherlist length
         *   41+x .  ..   cipherlist
         *    ..  .  ..   compression alg.
         */
        if( buf[0] != SSL_HS_CLIENT_HELLO ||
            buf[4] != SSLV3_MAJOR_VERSION )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        memcpy( ssl->max_ver, buf + 4, 2 );

        if( buf[1] != 0 || buf[2] != 0 || (int) buf[3] + 4 != n )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        memcpy( ssl->randbytes, buf + 6, 32 );

        sess_len = (int) buf[38];
        ciph_len = (int) buf[40 + sess_len];
        comp_len = (int) buf[41 + sess_len + ciph_len];

        if( buf[39 + sess_len] != 0 )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        if( ciph_len < 2 || ciph_len > 64 || ( ciph_len % 2 ) != 0 )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        if( n != 42 + sess_len + ciph_len + comp_len )
            return( ERR_SSL_BAD_HS_CLIENT_HELLO );

        for( i = 0; ssl->cipherlist[i] != 0; i++ )
        {
            for( j = 0; j < ciph_len; j += 2 )
            {
                if( buf[41 + sess_len + j] == 0 &&
                    buf[42 + sess_len + j] == ssl->cipherlist[i] )
                {
                    ssl->cipher = ssl->cipherlist[i];
                    return( 0 );
                }
            }
        }
    }

    return( ERR_SSL_NO_CIPHER_ACCEPTABLE );
}

int ssl_write_server_hello( ssl_context *ssl )
{
    uchar *buf;
    int i, n;
    time_t t;

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     */
    buf = ssl->out_msg;

    buf[4] = ssl->major_version;
    buf[5] = ssl->minor_version;

    t = time( NULL );
    buf[6] = (uchar)(t >> 24);
    buf[7] = (uchar)(t >> 16);
    buf[8] = (uchar)(t >>  8);
    buf[9] = (uchar)(t      );

    srand( (unsigned int) t );
    for( i = 4; i < 32; i++ )
        buf[i + 6] = (uchar) rand();

    memcpy( ssl->randbytes + 32, buf + 6, 32 );

    /*
     *    38  .  38   session id length
     *    39  . 38+x  session id
     *   39+x . 40+x  chosen cipher
     *   41+x . 41+x  chosen compression alg.
     */
    buf[38] = n = 16;
    srand( (unsigned int) t );
    for( i = 0; i < n; i++ )
        buf[i + 39] = (uchar) rand();

    buf[39 + n] = 0;
    buf[40 + n] = ssl->cipher;
    buf[41 + n] = SSL_COMPRESS_NULL;

    ssl->out_msglen  = 42 + n;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_HELLO;

    return( ssl_write_record( ssl, 0 ) );
}

int ssl_write_certificate_request( ssl_context *ssl )
{
    /*
     * TODO: handle client authentication
     */
    ssl = NULL;
    return( 0 );
}

int ssl_write_server_key_exchange( ssl_context *ssl )
{
    int ret, n;
    uchar hash[36];
    md5_context md5;
    sha1_context sha1;

    if( ssl->cipher != SSL3_EDH_RSA_DES_168_SHA &&
        ssl->cipher != TLS1_EDH_RSA_AES_256_SHA )
        return( 0 );

    /*
     * Ephemeral DH parameters:
     *
     * struct {
     *     opaque dh_p<1..2^16-1>;
     *     opaque dh_g<1..2^16-1>;
     *     opaque dh_Ys<1..2^16-1>;
     * } ServerDHParams;
     */
    if( ( ret = dhm_ssl_make_params( &ssl->dhm_ctx,
                                      ssl->out_msg + 4, &n,
                       ssl->rng_func, ssl->rng_state ) ) != 0 )
        return( ret );

    /*
     * digitally-signed struct {
     *     opaque md5_hash[16];
     *     opaque sha_hash[20];
     * };
     *
     * md5_hash
     *     MD5(ClientHello.random + ServerHello.random
     *                            + ServerParams);
     * sha_hash
     *     SHA(ClientHello.random + ServerHello.random
     *                            + ServerParams);
     */
    md5_starts( &md5 );
    md5_update( &md5, ssl->randbytes, 64  );
    md5_update( &md5, ssl->out_msg + 4, n );
    md5_finish( &md5, hash );

    sha1_starts( &sha1 );
    sha1_update( &sha1, ssl->randbytes, 64  );
    sha1_update( &sha1, ssl->out_msg + 4, n );
    sha1_finish( &sha1, hash + 16 );

    ssl->out_msg[4 + n] = (uchar)( ssl->own_key->len >> 8 );
    ssl->out_msg[5 + n] = (uchar)( ssl->own_key->len      );

    if( ( ret = rsa_pkcs1_sign( ssl->own_key, RSA_NONE,
                                hash, 36, ssl->out_msg + 6 + n,
                                ssl->own_key->len ) ) != 0 )
        return( ret );

    ssl->out_msglen  = 6 + n + ssl->own_key->len;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_KEY_EXCHANGE;

    return( ssl_write_record( ssl, 0 ) );
}

int ssl_write_server_hello_done( ssl_context *ssl )
{
    ssl->out_msglen  = 4;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_HELLO_DONE;

    return( ssl_write_record( ssl, 0 ) );
}

int ssl_parse_client_key_exchange( ssl_context *ssl )
{
    int ret, n1, n2, n3;

    if( ( ret = ssl_read_record( ssl, 0 ) ) != 0 )
        return( ret );

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        return( ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );

    if( ssl->in_msg[0] != SSL_HS_CLIENT_KEY_EXCHANGE )
        return( ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );

    if( ssl->cipher == SSL3_EDH_RSA_DES_168_SHA ||
        ssl->cipher == TLS1_EDH_RSA_AES_256_SHA )
    {
        /*
         * Receive G^Y mod P, premaster = (G^Y)^X mod P
         */
        n1 = ( ssl->in_msg[4] << 8 ) | ssl->in_msg[5];
        n2 = n1 + 6;

        if( n1 != ssl->dhm_ctx.len || n2 != ssl->hslen )
            return( ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );

        if( ( ret = dhm_read_public( &ssl->dhm_ctx,
                                      ssl->in_msg + 6, n1 ) ) != 0 )
            return( ret );

        if( ( ret = dhm_calc_secret( &ssl->dhm_ctx,
                                      ssl->premaster , n1 ) ) != 0 )
            return( ret );
    }
    else
    {
        /*
         * Decrypt the premaster using own private RSA key
         */
        n1 = 4;
        n2 = ssl->own_key->len;
        n3 = 48;

        if( ssl->minor_version != SSLV3_MINOR_VERSION )
        {
            n1 += 2;
            if( ssl->in_msg[4] != (uchar)( n2 >> 8 ) ||
                ssl->in_msg[5] != (uchar)  n2 )
                return( ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
        }

        if( ssl->hslen != n1 + n2 )
            return( ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );

        if( ( ret = rsa_pkcs1_decrypt( ssl->own_key,
                                       ssl->in_msg + n1, n2,
                                       ssl->premaster, &n3 ) ) != 0 )
            return( ret );

        if( n3 != 48 || memcmp( ssl->premaster, ssl->max_ver, 2 ) != 0 )
            return( ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    ssl_derive_keys( ssl );

    return( 0 );
}

int ssl_parse_certificate_verify( ssl_context *ssl )
{
    /*
     * TODO: handle client authentication
     */
    ssl = NULL;
    return( 0 );
}

/*
 * Perform an SSL handshake with the client; client_verify may be:
 *
 *  SSL_VERIFY_NONE: no client certificates are asked
 *
 *  SSL_VERIFY_OPTIONAL: client certificate is checked, however the
 *                       handshake continues even if verification failed
 *                       (you may want to check ssl->verify_result after)
 *
 *  SSL_VERIFY_REQUIRED: client *must* present a valid certificate,
 *                       handshake is aborted if verification failed.
 *
 * This function returns 0 when successful, or an SSL error code.
 */
int ssl_server_start( ssl_context *ssl, int client_verify )
{
    int ret;

    ssl->endpoint    = SSL_IS_SERVER;
    ssl->verify_mode = client_verify;

    /*
     *  <--  ClientHello
     */
    if( ( ret = ssl_parse_client_hello( ssl ) ) != 0 )
        return( ret );

    /*
     *  -->  ServerHello
     *       Certificate
     *      (CertificateRequest)
     *      (ServerKeyExchange)
     *       ServerHelloDone
     */

    if( ( ret = ssl_write_server_hello( ssl ) )         != 0 ||
        ( ret = ssl_write_certificate( ssl ) )          != 0 ||
        ( ret = ssl_write_certificate_request( ssl ) )  != 0 ||
        ( ret = ssl_write_server_key_exchange( ssl ) )  != 0 ||
        ( ret = ssl_write_server_hello_done( ssl ) )    != 0 )
        return( ret );

    /*
     *  <-- (Certificate/Alert)
     *       ClientKeyExchange
     *      (CertificateVerify)
     *       ChangeCipherSpec
     *       Finished
     */
    if( ( ret = ssl_parse_client_key_exchange( ssl ) ) != 0 ||
        ( ret = ssl_parse_certificate_verify( ssl ) )  != 0 ||
        ( ret = ssl_parse_change_cipher_spec( ssl ) )  != 0 ||
        ( ret = ssl_parse_finished( ssl ) )            != 0 )
        return( ret );

    /*
     *  -->  ChangeCipherSpec
     *       Finished
     */
    if( ( ret = ssl_write_change_cipher_spec( ssl ) )   != 0 ||
        ( ret = ssl_write_finished( ssl ) )             != 0 )
        return( ret );

    return( 0 );
}
