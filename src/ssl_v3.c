/*
 *  SSLv3/TLSv1 shared functions
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
/*
 *  The SSL 3.0 specification was drafted by Netscape in 1996,
 *  and became an IETF standard in 1999.
 *
 *  http://wp.netscape.com/eng/ssl3/
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "ssl_v3.h"
#include "x509.h"
#include "net.h"
#include "md5.h"
#include "sha1.h"
#include "arc4.h"
#include "des.h"
#include "aes.h"

/* 
 * Key material generation
 */
void tls1_prf( uchar *secret, uint seclen, char *label,
               uchar *random, uint rndlen, uchar *out, uint outlen )
{
    uint nb, hs;
    uint i, j, k;
    uchar *S1, *S2;
    uchar buf[128];
    uchar h_i[20];

    if( 20 + strlen( label ) + rndlen >= sizeof( buf ) )
        return;

    hs = ( seclen + 1 ) / 2;
    S1 = secret;
    S2 = secret + seclen - hs;

    nb = strlen( label );
    memcpy( buf + 20, label, nb );
    memcpy( buf + 20 + nb, random, rndlen );
    nb += rndlen;

    /*
     * First compute P_md5(secret,label+random)[0..outlen]
     */
    md5_hmac( S1, hs, buf + 20, nb, 4 + buf );

    for( i = 0; i < outlen; i += 16 )
    {
        md5_hmac( S1, hs, 4 + buf, 16 + nb, h_i );
        md5_hmac( S1, hs, 4 + buf, 16,  4 + buf );

        k = ( i + 16 <= outlen ) ? 16 : outlen % 16;
        for( j = 0; j < k; j++ ) out[i + j] = h_i[j];

    }

    /*
     * XOR out with P_sha1(secret,label+random)[0..outlen]
     */
    sha1_hmac( S2, hs, buf + 20, nb, buf );

    for( i = 0; i < outlen; i += 20 )
    {
        sha1_hmac( S2, hs, buf, 20 + nb, h_i );
        sha1_hmac( S2, hs, buf, 20,      buf );

        k = ( i + 20 <= outlen ) ? 20 : outlen % 20;
        for( j = 0; j < k; j++ ) out[i + j] ^= h_i[j];
    }
}

int ssl_derive_keys( ssl_context *ssl )
{
    int i;
    md5_context md5;
    sha1_context sha1;
    uchar padding[10];
    uchar sha1sum[20];
    uchar keyblk[256];
    uchar *key1, *key2;
    void  *ctx1, *ctx2;
    int keylen, ctxlen;

    /*
     *  SSLv3:
     *    master =
     *      MD5( premaster + SHA1( 'A'   + premaster + randbytes ) ) +
     *      MD5( premaster + SHA1( 'BB'  + premaster + randbytes ) ) +
     *      MD5( premaster + SHA1( 'CCC' + premaster + randbytes ) )
     *
     *  TLSv1:
     *    master = PRF( premaster, "master secret", randbytes )[0..47]
     */
    if( ssl->minor_version == SSLV3_MINOR_VERSION )
    {
        for( i = 0; i < 3; i++ )
        {
            memset( padding, 'A' + i, i + 1 );

            sha1_starts( &sha1 );
            sha1_update( &sha1, padding, i + 1 );
            sha1_update( &sha1, ssl->premaster, 48 );
            sha1_update( &sha1, ssl->randbytes, 64 );
            sha1_finish( &sha1, sha1sum );

            md5_starts( &md5 );
            md5_update( &md5, ssl->premaster, 48 );
            md5_update( &md5, sha1sum, 20 );
            md5_finish( &md5, ssl->master + i * 16 );
        }
    }
    else
        tls1_prf( ssl->premaster, 48, "master secret",
                  ssl->randbytes, 64, ssl->master, 48 );

    memset( ssl->premaster, 0, sizeof( ssl->premaster ) );

    /*
     *  SSLv3:
     *    key block =
     *      MD5( master + SHA1( 'A'    + master + randbytes ) ) +
     *      MD5( master + SHA1( 'BB'   + master + randbytes ) ) +
     *      MD5( master + SHA1( 'CCC'  + master + randbytes ) ) +
     *      MD5( master + SHA1( 'DDDD' + master + randbytes ) ) +
     *      ...
     *
     *  TLSv1:
     *    key block = PRF( master, "key expansion", randbytes )
     */
    {
        /*
         * Swap the client and server random values.
         */
        uchar tmp[64];

        memcpy( tmp, ssl->randbytes, 64 );
        memcpy( ssl->randbytes, tmp + 32, 32 );
        memcpy( ssl->randbytes + 32, tmp, 32 );
        memset( tmp, 0, sizeof( tmp ) );
    }

    if( ssl->minor_version == SSLV3_MINOR_VERSION )
    {
        for( i = 0; i < 16; i++ )
        {
            memset( padding, 'A' + i, i + 1 );

            sha1_starts( &sha1 );
            sha1_update( &sha1, padding, i + 1 );
            sha1_update( &sha1, ssl->master, 48 );
            sha1_update( &sha1, ssl->randbytes, 64 );
            sha1_finish( &sha1, sha1sum );

            md5_starts( &md5 );
            md5_update( &md5, ssl->master, 48 );
            md5_update( &md5, sha1sum, 20 );
            md5_finish( &md5, keyblk + i * 16 );
        }

        memset( &md5,    0, sizeof( md5     ) );
        memset( &sha1,   0, sizeof( sha1    ) );
        memset( padding, 0, sizeof( padding ) );
        memset( sha1sum, 0, sizeof( sha1sum ) );
    }
    else
        tls1_prf( ssl->master, 48, "key expansion",
                  ssl->randbytes, 64, keyblk, 256 );

    memset( ssl->randbytes, 0, sizeof( ssl->randbytes ) );

    /*
     * Determine the appropriate key, IV and MAC length.
     */
    switch( ssl->cipher )
    {
        case SSL3_RSA_RC4_128_MD5:
            ssl->maclen = 16; keylen = 16; ssl->ivlen =  0;
            ssl->minlen = 16; ctxlen = sizeof( arc4_context );
            break;

        case SSL3_RSA_RC4_128_SHA:
            ssl->maclen = 20; keylen = 16; ssl->ivlen =  0;
            ssl->minlen = 20; ctxlen = sizeof( arc4_context );
            break;

        case SSL3_RSA_DES_192_SHA:
            ssl->maclen = 20; keylen = 24; ssl->ivlen =  8;
            ssl->minlen = 24; ctxlen = sizeof( des3_context );
            break;

        case TLS1_RSA_AES_256_SHA:
            ssl->maclen = 20; keylen = 32; ssl->ivlen = 16;
            ssl->minlen = 32; ctxlen = sizeof( aes_context  );
            break;

        default:
            return( ERR_SSL_UNKNOWN_CIPHER );
    }

    /*
     * Finally setup the cipher contexts, IVs and MAC secrets.
     */
    key1 = keyblk + ssl->maclen * 2;
    key2 = keyblk + ssl->maclen * 2 + keylen;

    if( ( ctx1 = (void *) malloc( ctxlen ) ) == NULL ||
        ( ctx2 = (void *) malloc( ctxlen ) ) == NULL )
        return( 1 );

    switch( ssl->cipher )
    {
        case SSL3_RSA_RC4_128_MD5:
        case SSL3_RSA_RC4_128_SHA:
            arc4_setup( ctx1, key1, keylen );
            arc4_setup( ctx2, key2, keylen );
            break;

        case SSL3_RSA_DES_192_SHA:
            des3_set_3keys( ctx1, key1 );
            des3_set_3keys( ctx2, key2 );
            break;

        case TLS1_RSA_AES_256_SHA:
            aes_set_key( ctx1, key1, 256 );
            aes_set_key( ctx2, key2, 256 );
            break;

        default:
            return( ERR_SSL_UNKNOWN_CIPHER );
    }

    if( ssl->endpoint == SSL_IS_CLIENT )
    {
        memcpy( ssl->mac_enc, keyblk,  ssl->maclen );
        memcpy( ssl->mac_dec, keyblk + ssl->maclen, ssl->maclen );

        ssl->encrypt_ctx = ctx1;
        ssl->decrypt_ctx = ctx2;

        memcpy( ssl->iv_enc, key2 + keylen,  ssl->ivlen );
        memcpy( ssl->iv_dec, key2 + keylen + ssl->ivlen, ssl->ivlen );
    }
    else
    {
        memcpy( ssl->mac_dec, keyblk,  ssl->maclen );
        memcpy( ssl->mac_enc, keyblk + ssl->maclen, ssl->maclen );

        ssl->decrypt_ctx = ctx1;
        ssl->encrypt_ctx = ctx2;

        memcpy( ssl->iv_dec, key2 + keylen,  ssl->ivlen );
        memcpy( ssl->iv_enc, key2 + keylen + ssl->ivlen, ssl->ivlen );
    }

    ssl->ctxlen = ctxlen;
    ssl->do_crypt = 1;

    memset( keyblk,  0, sizeof( keyblk ) );

    return( 0 );
}

/* 
 * SSLv3 MAC functions
 */
void ssl_mac_md5( uchar *key, uchar *buf, uint len,
                  uchar *ctr, uint type )
{
    uchar header[11];
    uchar padding[48];
    md5_context md5;

    memcpy( header, ctr, 8 );
    header[ 8] = type;
    header[ 9] = (len >> 8);
    header[10] =  len;

    memset( padding, 0x36, 48 );
    md5_starts( &md5 );
    md5_update( &md5, key, 16 );
    md5_update( &md5, padding, 48 );
    md5_update( &md5, header, 11 );
    md5_update( &md5, buf, len );
    md5_finish( &md5, buf + len );

    memset( padding, 0x5C, 48 );
    md5_starts( &md5 );
    md5_update( &md5, key, 16 );
    md5_update( &md5, padding, 48 );
    md5_update( &md5, buf + len, 16 );
    md5_finish( &md5, buf + len);
}

void ssl_mac_sha1( uchar *key, uchar *buf, uint len,
                   uchar *ctr, uint type )
{
    uchar header[11];
    uchar padding[40];
    sha1_context sha1;

    memcpy( header, ctr, 8 );
    header[ 8] = type;
    header[ 9] = (len >> 8);
    header[10] =  len;

    memset( padding, 0x36, 40 );
    sha1_starts( &sha1 );
    sha1_update( &sha1, key, 20 );
    sha1_update( &sha1, padding, 40 );
    sha1_update( &sha1, header, 11 );
    sha1_update( &sha1, buf, len );
    sha1_finish( &sha1, buf + len );

    memset( padding, 0x5C, 40 );
    sha1_starts( &sha1 );
    sha1_update( &sha1, key, 20 );
    sha1_update( &sha1, padding, 40 );
    sha1_update( &sha1, buf + len, 20 );
    sha1_finish( &sha1, buf + len);
}

/* 
 * Message encryption/decryption
 */ 
int ssl_encrypt_buf( ssl_context *ssl )
{
    int i;
    uint padlen;

    if( ssl->do_crypt == 0 )
        return( 0 );

    /*
     * Add MAC then encrypt
     */
    if( ssl->minor_version == SSLV3_MINOR_VERSION )
    {
        if( ssl->maclen == 16 )
             ssl_mac_md5( ssl->mac_enc, ssl->out_msg, ssl->out_msglen,
                          ssl->out_ctr, ssl->out_msgtype );

        if( ssl->maclen == 20 )
            ssl_mac_sha1( ssl->mac_enc, ssl->out_msg, ssl->out_msglen,
                          ssl->out_ctr, ssl->out_msgtype );
    }
    else
    {
        if( ssl->maclen == 16 )
             md5_hmac( ssl->mac_enc, 16, ssl->out_ctr,
                       ssl->out_msglen + 13,
                       ssl->out_msg + ssl->out_msglen );

        if( ssl->maclen == 20 )
            sha1_hmac( ssl->mac_enc, 20, ssl->out_ctr,
                       ssl->out_msglen + 13,
                       ssl->out_msg + ssl->out_msglen );               
    }

    ssl->out_msglen += ssl->maclen;

    for( i = 7; i >= 0; i-- )
        if( ++ssl->out_ctr[i] != 0 )
            break;

    if( ssl->ivlen == 0 )
    {
        arc4_crypt( ssl->encrypt_ctx, ssl->out_msg, ssl->out_msglen );
        padlen = 0;
    }
    else
    {
        padlen = ssl->ivlen - ( ssl->out_msglen + 1 ) % ssl->ivlen;

        for( i = 0; i <= (int) padlen; i++ )
            ssl->out_msg[ssl->out_msglen + i] = padlen;

        ssl->out_msglen += padlen + 1;

        if( ssl->ivlen ==  8 )
            des3_cbc_encrypt( ssl->encrypt_ctx, ssl->iv_enc,
                              ssl->out_msg, ssl->out_msg,
                              ssl->out_msglen );

        if( ssl->ivlen == 16 )
            aes_cbc_encrypt( ssl->encrypt_ctx, ssl->iv_enc,
                             ssl->out_msg, ssl->out_msg,
                             ssl->out_msglen );
    }

    return( 0 );
}

int ssl_decrypt_buf( ssl_context *ssl )
{
    int i;
    uint padlen;
    uchar tmp[20];

    if( ssl->do_crypt == 0 )
        return( 0 );

    if( ssl->in_msglen < ssl->minlen )
        return( ERR_SSL_INVALID_MAC );

    if( ssl->ivlen == 0 )
    {
        arc4_crypt( ssl->decrypt_ctx,
                    ssl->in_msg, ssl->in_msglen );
        padlen = 0;
    }
    else
    {
        /*
         * Decrypt and check the padding
         */
        if( ssl->in_msglen % ssl->ivlen != 0 )
            return( ERR_SSL_INVALID_MAC );

        if( ssl->ivlen ==  8 )
            des3_cbc_decrypt( ssl->decrypt_ctx, ssl->iv_dec,
                              ssl->in_msg, ssl->in_msg,
                              ssl->in_msglen );

        if( ssl->ivlen == 16 )
             aes_cbc_decrypt( ssl->decrypt_ctx, ssl->iv_dec,
                              ssl->in_msg, ssl->in_msg,
                              ssl->in_msglen );

        padlen = 1 + (uint) ssl->in_msg[ssl->in_msglen - 1];

        if( ssl->minor_version == SSLV3_MINOR_VERSION )
        {
            if( padlen > ssl->ivlen )
                padlen = 0;
        }
        else
        {
            for( i = 1; i <= (int) padlen; i++ )
                if( ssl->in_msg[ssl->in_msglen - i] != padlen - 1 )
                    padlen = 0;
        }
    }

    /*
     * Always compute the MAC (RFC4346, CBCTIME).
     */
    ssl->in_msglen -= ( ssl->maclen + padlen );

    ssl->in_hdr[3] = ssl->in_msglen >>  8;
    ssl->in_hdr[4] = ssl->in_msglen;

    memcpy( tmp, ssl->in_msg + ssl->in_msglen, 20 );

    if( ssl->minor_version == SSLV3_MINOR_VERSION )
    {
        if( ssl->maclen == 16 )
             ssl_mac_md5( ssl->mac_dec,
                          ssl->in_msg, ssl->in_msglen,
                          ssl->in_ctr, ssl->in_msgtype );
        else
            ssl_mac_sha1( ssl->mac_dec,
                          ssl->in_msg, ssl->in_msglen,
                          ssl->in_ctr, ssl->in_msgtype );
    }
    else
    {
        if( ssl->maclen == 16 )
             md5_hmac( ssl->mac_dec, 16,
                       ssl->in_ctr,  ssl->in_msglen + 13,
                       ssl->in_msg + ssl->in_msglen );
        else
            sha1_hmac( ssl->mac_dec, 20,
                       ssl->in_ctr,  ssl->in_msglen + 13,
                       ssl->in_msg + ssl->in_msglen );
    }

    if( memcmp( tmp, ssl->in_msg + ssl->in_msglen,
                     ssl->maclen ) != 0 )
        return( ERR_SSL_INVALID_MAC );

    /*
     * Finally verify the padding length; bad padding
     * will produce the same error as an invalid MAC.
     */
    if( ssl->ivlen != 0 && padlen == 0 )
        return( ERR_SSL_INVALID_MAC );

    /*
     * Two or more empty messages may be a DoS attack.
     */
    if( ssl->in_msglen == 0 &&
        ssl->in_prvlen == 0 )
        return( ERR_SSL_INVALID_MAC );

    for( i = 7; i >= 0; i-- )
        if( ++ssl->in_ctr[i] != 0 )
            break;

    return( 0 );
}

/* 
 * Record layer functions
 */
int ssl_write_record( ssl_context *ssl )
{
    int ret;
    uint len = ssl->out_msglen;

    ssl->out_hdr[0] = ssl->out_msgtype;
    ssl->out_hdr[1] = ssl->major_version;
    ssl->out_hdr[2] = ssl->minor_version;
    ssl->out_hdr[3] = len >> 8;
    ssl->out_hdr[4] = len;

    if( ssl->out_msgtype == SSL_MSG_HANDSHAKE )
    {
        ssl->out_msg[1] = (len - 4) >> 16;
        ssl->out_msg[2] = (len - 4) >>  8;
        ssl->out_msg[3] = (len - 4);

         md5_update( &ssl-> md5_handshake, ssl->out_msg, len );
        sha1_update( &ssl->sha1_handshake, ssl->out_msg, len );
    }

    if( ( ret = ssl_encrypt_buf( ssl ) ) != 0 )
        return( ret );

    len = ssl->out_msglen;
    ssl->out_hdr[3] = len >> 8;
    ssl->out_hdr[4] = len;

    return( net_write_all( ssl->write_fd, ssl->out_hdr, len + 5 ) );
}

int ssl_read_record( ssl_context *ssl )
{
    int ret;
    uint i, len;

    if( ssl->in_msgtype == SSL_MSG_HANDSHAKE &&
        ssl->in_msglen > ssl->hslen )
    {
        /*
         * Get next Handshake in current record
         */
        ssl->in_msglen -= ssl->hslen;

        for( i = 0; i < ssl->in_msglen; i++ )
            ssl->in_msg[i] = ssl->in_msg[i + ssl->hslen];

        if( ssl->in_msglen < 4 || ssl->in_msg[1] != 0 )
            return( ERR_SSL_INVALID_RECORD );

        ssl->hslen = 4 + ( ( ssl->in_msg[2] << 8 )
                           | ssl->in_msg[3] );

        if( ssl->in_msglen < ssl->hslen )
            return( ERR_SSL_INVALID_RECORD );

        return( 0 );
    }

    /*
     * Read the record header and validate it
     */
    if( ( ret = net_read_all( ssl->read_fd,
                              ssl->in_hdr, 5 ) ) != 0 )
        return( ret );

    ssl->in_msgtype = ssl->in_hdr[0];
    ssl->in_prvlen  = ssl->in_msglen;
    ssl->in_msglen  = len = ( ssl->in_hdr[3] << 8 )
                            | ssl->in_hdr[4];

    if( ssl->in_hdr[1] != ssl->major_version ||
        len < 1 || len  > SSL_MAX_RECORD_LEN )
        return( ERR_SSL_INVALID_RECORD );

    if( ( ret = net_read_all( ssl->read_fd,
                              ssl->in_msg, len ) ) != 0 )
        return( ret );

    if( ssl->in_msgtype != SSL_MSG_CHANGE_CIPHER_SPEC )
        if( ( ret = ssl_decrypt_buf( ssl ) ) != 0 )
            return( ret );

    if( ssl->in_hdr[2] != ssl->minor_version )
    {
        /*
         * Only in ServerHello can the minor version vary
         */
        if( ssl->in_hdr[2] != SSLV3_MINOR_VERSION &&
            ssl->in_hdr[2] != TLS10_MINOR_VERSION )
            return( ERR_SSL_INVALID_RECORD );

        if( ssl->in_msgtype != SSL_MSG_HANDSHAKE &&
            ssl->in_msg[0]  != SSL_HS_SERVER_HELLO )
            return( ERR_SSL_INVALID_RECORD );
    }

    if( ssl->in_msgtype == SSL_MSG_HANDSHAKE )
    {
        /*
         * Additional checks to validate the handshake header
         */
        if( len < 4 || ssl->in_msg[1] != 0 )
            return( ERR_SSL_INVALID_RECORD );

        ssl->hslen = 4 + (( ssl->in_msg[2] << 8 ) | ssl->in_msg[3]);

        if( ssl->in_msglen < ssl->hslen )
            return( ERR_SSL_INVALID_RECORD );

        if( ssl->in_msg[0] != SSL_HS_FINISHED ||
            ssl->endpoint  == SSL_IS_SERVER )
        {
              md5_update( &ssl-> md5_handshake, ssl->in_msg,
                          ssl->in_msglen );

             sha1_update( &ssl->sha1_handshake, ssl->in_msg,
                          ssl->in_msglen );
        }
    }
    else
        ssl->hslen = ~0;

    if( ssl->in_msgtype == SSL_MSG_ALERT )
    {
        memcpy( ssl->in_alert, ssl->in_msg, 2 );

        if( ssl->in_alert[0] == SSL_ALERT_FATAL )
            return( ERR_SSL_FATAL_ALERT_MESSAGE );

        if( ssl->in_alert[0] == SSL_ALERT_WARNING &&
            ssl->in_alert[1] == SSL_ALERT_CLOSE_NOTIFY )
            return( ERR_SSL_PEER_CLOSE_NOTIFY );
    }

    return( 0 );
}

/* 
 * Handshake functions
 */
int ssl_parse_certificate( ssl_context *ssl )
{
    int ret;
    uint i, n;

    /*
     *     0  .  0    handshake type
     *     1  .  3    handshake length
     *     4  .  6    length of all certs
     *     7  .  9    length of cert. 1
     *    10  . n-1   peer certificate
     *     n  . n+2   length of cert. 2
     *    n+3 . ...   upper level cert, etc.
     */
    if( ( ret = ssl_read_record( ssl ) ) != 0 )
        return( ret );

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        return( ERR_SSL_UNEXPECTED_MESSAGE );

    if( ssl->in_msg[0] != SSL_HS_CERTIFICATE || ssl->hslen < 10 )
        return( ERR_SSL_BAD_HS_CERTIFICATE );

    n = ( ssl->in_msg[5] << 8 ) | ssl->in_msg[6];

    if( ssl->in_msg[4] != 0 || ssl->hslen != 7 + n )
        return( ERR_SSL_BAD_HS_CERTIFICATE );

    if( ( ssl->peer_cert = (x509_cert *) malloc(
                    sizeof( x509_cert ) ) ) == NULL )
        return( 1 );

    memset( ssl->peer_cert, 0, sizeof( x509_cert ) );
    i = 7;

    while( i < ssl->hslen )
    {
        if( ssl->in_msg[i] != 0 )
            return( ERR_SSL_BAD_HS_CERTIFICATE );

        n = ( ssl->in_msg[i + 1] << 8 ) | ssl->in_msg[i + 2];
        i += 3;

        if( n < 128 || i + n > ssl->hslen )
            return( ERR_SSL_BAD_HS_CERTIFICATE );

        ret = x509_add_certs( ssl->peer_cert, ssl->in_msg + i, n );
        if( ret != 0 )
            return( ret );

        i += n;
    }

    if( ssl->verify_mode != SSL_VERIFY_NONE )
    {
        if( ssl->ca_chain == NULL )
            return( ERR_SSL_CA_CHAIN_REQUIRED );

        ret = x509_verify_cert( ssl->peer_cert, ssl->ca_chain,
                                ssl->peer_cn, &ssl->verify_result );

        if( ssl->verify_mode == SSL_VERIFY_OPTIONAL )
            return( 0 );
    }

    return( ret );
}

int ssl_write_certificate( ssl_context *ssl )
{
    uint i, n;
    x509_cert *crt;

    if( ssl->own_cert == NULL )
    {
        if( ssl->endpoint == SSL_IS_SERVER )
            return( ERR_SSL_CERTIFICATE_REQUIRED );

        if( ssl->endpoint == SSL_IS_CLIENT &&
            ssl->client_auth != 0 )
        {
            /*
             * TODO: send an alert message (SSLv3) or an
             * empty certificate (TLSv1.0)
             */
            return( ERR_SSL_CERTIFICATE_REQUIRED );
        }

        return( 0 );
    }

    /*
     * Same message structure as shown above
     */
    i = 7;
    crt = ssl->own_cert;
    while( crt != NULL )
    {
        n = crt->raw.len;

        if( i + 3 + n > SSL_MAX_RECORD_LEN )
            return( ERR_SSL_CERTIFICATE_TOO_LARGE );

        ssl->out_msg[i] = 0;
        ssl->out_msg[i] = n >>  8;
        ssl->out_msg[i] = n >> 16;

        i += 3; memcpy( ssl->out_msg + i, crt->raw.p, n );
        i += n; crt = crt->next;
    }

    ssl->out_msg[4] = 0;
    ssl->out_msg[5] = (n - 7) >> 8;
    ssl->out_msg[6] = (n - 7);

    ssl->out_msglen  = i;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE;

    return( ssl_write_record( ssl ) );
}

int ssl_parse_change_cipher_spec( ssl_context *ssl )
{
    int ret;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
        return( ret );

    if( ssl->in_msgtype != SSL_MSG_CHANGE_CIPHER_SPEC )
        return( ERR_SSL_UNEXPECTED_MESSAGE );

    if( ssl->in_msglen != 1 || ssl->in_msg[0] != 1 )
        return( ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );

    return( 0 );
}

int ssl_write_change_cipher_spec( ssl_context *ssl )
{
    ssl->out_msgtype = SSL_MSG_CHANGE_CIPHER_SPEC;
    ssl->out_msg[0]  = ssl->out_msglen = 1;

    return( ssl_write_record( ssl ) );
}

void ssl_calc_finished( ssl_context *ssl, uchar *buf, int from )
{
    char *sender;
    uchar padbuf[48];
    uchar md5sum[16];
    uchar sha1sum[20];
    md5_context md5;
    sha1_context sha1;

    /*
     * SSLv3:
     *   hash =
     *      MD5( master + pad2 +
     *          MD5( handshake + sender + master + pad1 ) )
     *   + SHA1( master + pad2 +
     *         SHA1( handshake + sender + master + pad1 ) )
     *
     * TLSv1:
     *   hash = PRF( master, finished_label,
     *               MD5( handshake ) + SHA1( handshake ) )[0..11]
     */
    if( ssl->minor_version == SSLV3_MINOR_VERSION )
    {
        sender = ( from == SSL_IS_CLIENT ) ? "CLNT" : "SRVR";

        memcpy(  &md5,  &ssl->md5_handshake, sizeof(  md5 ) );
        memcpy( &sha1, &ssl->sha1_handshake, sizeof( sha1 ) );

        memset( padbuf, 0x36, 48 );

        md5_update( &md5, (uchar *) sender, 4 );
        md5_update( &md5, ssl->master, 48 );
        md5_update( &md5, padbuf, 48 );
        md5_finish( &md5, md5sum );

        sha1_update( &sha1, (uchar *) sender, 4 );
        sha1_update( &sha1, ssl->master, 48 );
        sha1_update( &sha1, padbuf, 40 );
        sha1_finish( &sha1, sha1sum );

        memset( padbuf, 0x5C, 48 );

        md5_starts( &md5 );
        md5_update( &md5, ssl->master, 48 );
        md5_update( &md5, padbuf, 48 );
        md5_update( &md5, md5sum, 16 );
        md5_finish( &md5, buf );

        sha1_starts( &sha1 );
        sha1_update( &sha1, ssl->master, 48 );
        sha1_update( &sha1, padbuf, 40 );
        sha1_update( &sha1, sha1sum, 20 );
        sha1_finish( &sha1, buf + 16 );
    }
    else
    {
        sender = ( from == SSL_IS_CLIENT ) ? "client finished"
                                           : "server finished";

        memcpy( & md5, &ssl-> md5_handshake, sizeof(  md5 ) );
        memcpy( &sha1, &ssl->sha1_handshake, sizeof( sha1 ) );

         md5_finish(  &md5, padbuf );
        sha1_finish( &sha1, padbuf + 16 );

        tls1_prf( ssl->master, 48, sender, padbuf, 36, buf, 12 );
    }

    memset(  &md5, 0, sizeof(  md5_context ) );
    memset( &sha1, 0, sizeof( sha1_context ) );

    memset(  md5sum, 0, sizeof(  md5sum ) );
    memset( sha1sum, 0, sizeof( sha1sum ) );
}

int ssl_parse_finished( ssl_context *ssl )
{
    int ret;
    uint hash_len;
    uchar buf[36];

    if( ssl->do_crypt == 0 )
        ssl_derive_keys( ssl );

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
        return( ret );

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        return( ERR_SSL_UNEXPECTED_MESSAGE );

    if( ssl->minor_version == SSLV3_MINOR_VERSION )
         hash_len = 36;
    else hash_len = 12;

    if( *ssl->in_msg != SSL_HS_FINISHED ||
         ssl->hslen  != 4 + hash_len )
        return( ERR_SSL_BAD_HS_FINISHED );

    ssl_calc_finished( ssl, buf, ssl->endpoint ^ 1 );

    if( memcmp( ssl->in_msg + 4, buf, hash_len ) != 0 )
        return( ERR_SSL_BAD_HS_FINISHED );

    return( 0 );
}

int ssl_write_finished( ssl_context *ssl )
{
    uint hash_len;

    if( ssl->do_crypt == 0 )
        ssl_derive_keys( ssl );

    if( ssl->minor_version == SSLV3_MINOR_VERSION )
         hash_len = 36;
    else hash_len = 12;

    ssl->out_msglen  = 4 + hash_len;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_FINISHED;

    ssl_calc_finished( ssl, ssl->out_msg + 4, ssl->endpoint );

    return( ssl_write_record( ssl ) );
}

/*
 * Setup the list of allowed ciphers and the RNG context.
 * Also allocate memory for the input and output buffers;
 * returns 1 if allocation failed, or 0 if successful.
 */
int ssl_init( ssl_context *ssl, uint *cipherlist,
              ulong (*rng_func)(void *), void *rng_state )
{
    memset( ssl, 0, sizeof( ssl_context ) );

    ssl->major_version  = SSLV3_MAJOR_VERSION;
    ssl->minor_version  = SSLV3_MINOR_VERSION;
    ssl->cipherlist     = cipherlist;
    ssl->rng_func       = rng_func;
    ssl->rng_state      = rng_state;

    ssl-> in_ctr = (uchar *) malloc( SSL_MAX_RECORD_LEN + 1 );
    ssl->out_ctr = (uchar *) malloc( SSL_MAX_RECORD_LEN + 1 );

    if( ssl->in_ctr == NULL || ssl->out_ctr == NULL )
        return( 1 );

    memset( ssl-> in_ctr, 0, SSL_MAX_RECORD_LEN + 1 );
    memset( ssl->out_ctr, 0, SSL_MAX_RECORD_LEN + 1 );

    ssl->in_hdr = ssl->in_ctr +  8;
    ssl->in_msg = ssl->in_ctr + 13;

    ssl->out_hdr = ssl->out_ctr +  8;
    ssl->out_msg = ssl->out_ctr + 13;

    return( 0 );
}

/*
 * Setup own certificate and private key struct, returns 0.
 */
int ssl_set_owncert( ssl_context *ssl, x509_cert *own_cert,
                     rsa_context *own_key )
{
    ssl->own_cert = own_cert;
    ssl->own_key  = own_key;

    return( 0 );
}

/*
 * Setup the CA cert chain used to verify peer cert and expected CN.
 */
int ssl_set_ca_chain( ssl_context *ssl, x509_cert *ca, char *cn )
{
    ssl->ca_chain = ca;
    ssl->peer_cn  = cn;

    return( 0 );
}

/*
 * Receive application data decrypted from the SSL layer.
 * If "full" is not null, exactly *len bytes will be read;
 * otherwise the result of the read (stored in *len) may
 * be lesser than the requested size.
 *
 * In both cases, this function will block until data is
 * received at the record layer.
 */
int ssl_read( ssl_context *ssl, uchar *buf, uint *len, int full )
{
    int ret;
    uint q, n = 0;

    while( n < *len )
    {
        if( ssl->left == 0 )
        {
            if( ( ret = ssl_read_record( ssl ) ) != 0 )
                return( ret );

            if( ssl->in_msgtype != SSL_MSG_APPLICATION_DATA )
                return( ERR_SSL_UNEXPECTED_MESSAGE );

            ssl->left = ssl->in_msglen;
        }

        q = ( ( *len - n ) < ssl->left )
            ? ( *len - n ) : ssl->left;

        memcpy( buf + n, ssl->in_msg +
                         ssl->in_msglen - ssl->left, q );
        n += q;
        ssl->left -= q;

        if( full == 0 && n > 0 )
        {
            *len = q;
            break;
        }
    }

    return( 0 );
}

/*
 * Send application data to be encrypted by the SSL layer;
 * peer will receive exactly len bytes.
 */
int ssl_write( ssl_context *ssl, uchar *buf, uint len )
{
    int ret;
    uint n;

    while( len > 0 )
    {
        n = ( len < SSL_MAX_RECORD_LEN )
            ? len : SSL_MAX_RECORD_LEN;

        ssl->out_msglen  = n;
        ssl->out_msgtype = SSL_MSG_APPLICATION_DATA;
        memcpy( ssl->out_msg, buf, n );

        if( ( ret = ssl_write_record( ssl ) ) != 0 )
            return( ret );

        len -= n;
    }

    return( 0 );
}

/*
 * Close the SSL connection. The context can be reused
 * afterwards (no need to call ssl_init again).
 */
void ssl_close( ssl_context *ssl )
{
    ssl->out_msgtype = SSL_MSG_ALERT;
    ssl->out_msglen = 2;
    ssl->out_msg[0] = SSL_ALERT_WARNING;
    ssl->out_msg[1] = SSL_ALERT_CLOSE_NOTIFY;
    ssl_write_record( ssl );

    net_close( ssl->read_fd  );
    net_close( ssl->write_fd );
}

/*
 * Cleanup the secrets and free all data; context cannot be used
 * anymore without calling ssl_init() first.
 */
void ssl_free( ssl_context *ssl )
{
    x509_cert *next;

    if( ssl->ctxlen != 0 )
    {
        memset( ssl->encrypt_ctx, 0, ssl->ctxlen );
        memset( ssl->decrypt_ctx, 0, ssl->ctxlen );
        free( ssl->encrypt_ctx );
        free( ssl->decrypt_ctx );
    }

    while( ssl->peer_cert != NULL )
    {
        next = ssl->peer_cert->next;
        memset( ssl->peer_cert, 0, sizeof( x509_cert ) );
        free( ssl->peer_cert );
        ssl->peer_cert = next;
    }

    memset( ssl-> in_ctr, 0, SSL_MAX_RECORD_LEN + 1 );
    memset( ssl->out_ctr, 0, SSL_MAX_RECORD_LEN + 1 );
    free( ssl-> in_ctr );
    free( ssl->out_ctr );
 
    memset( ssl, 0, sizeof( ssl_context ) );
}
